//! 发送方向：一次完整的 prepare → upload 会话，蓝本是 `cli/src/send_task.rs`。
//!
//! 与 CLI 的差别只在"结果怎么出去"：CLI 塞进终端事件枚举，这里全部走 JSON 事件泵。
//! 取消令牌必须留在 Rust 侧（`CancellationToken` 跨不了 FFI），宿主只拿一个自己生成的
//! `sendId` —— `prepare_upload` 还没回来时用户就可能取消，那时服务端的 sessionId 还不存在。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use localsend::crypto::hash::sha256_file_content;
use localsend::http::client::ClientError;
use localsend::http::client::LsHttpClientV2;
use localsend::http::dto_v2::PrepareUploadRequestDtoV2;
use localsend::model::discovery::ProtocolType;
use localsend::model::transfer::{FileContent, FileDto, FileMetadata};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use crate::bridge;
use crate::identity::Identity;
use crate::runtime;
use crate::state;
use crate::state::ValueExt as _;

/// 进度事件节流，与上游 FRB 层一致
const PROGRESS_INTERVAL: Duration = Duration::from_millis(20);

struct FileSpec {
    id: String,
    file_name: String,
    size: u64,
    file_type: String,
    sha256: Option<String>,
    path: Option<String>,
    fd: Option<i32>,
    hash_fd: Option<i32>,
}

struct Target {
    host: String,
    port: u16,
    protocol: ProtocolType,
    fingerprint: Option<String>,
}

struct SendSpec {
    send_id: String,
    target: Target,
    pin: Option<String>,
    compute_checksums: bool,
    timeout: Option<Duration>,
    files: Vec<FileSpec>,
}

/// 受理即返回 `sendId`，全过程走事件。
pub fn start(args: &Value) -> Result<Value, String> {
    let spec = parse_spec(args)?;
    let identity = state::identity()?;
    let token = CancellationToken::new();
    state::register_token(&spec.send_id, token.clone());
    let send_id = spec.send_id.clone();
    runtime::spawn(async move {
        let outcome = run_send(identity, spec, token).await;
        state::forget_token(&send_id);
        if let Err(error) = outcome {
            bridge::emit(
                "send.ended",
                json!({ "sendId": send_id, "result": "error", "error": error }),
            );
        }
    });
    Ok(json!({ "sendId": spec_send_id(args) }))
}

pub fn cancel(args: &Value) -> Result<Value, String> {
    let send_id = args.string("sendId").ok_or("sendId is required")?;
    state::cancel_token(&send_id);
    Ok(json!({ "sendId": send_id }))
}

/// 参数校验（同步）：没有可读源就当场报参数错，不占一次 reply 往返。
pub fn validate_hash(args: &Value) -> Result<(), String> {
    hash_content(args).map(|_| ())
}

/// 分块 SHA-256：进度走 `hash.progress`，结果由 call.rs 兑现成 reply。
pub async fn hash_file(args: Value) -> Result<Value, String> {
    let content = hash_content(&args)?;
    let token = CancellationToken::new();
    let throttle = Arc::new(std::sync::Mutex::new(Instant::now() - PROGRESS_INTERVAL));
    sha256_file_content(content, &token, move |bytes| {
        let mut last = throttle.lock().unwrap();
        if last.elapsed() < PROGRESS_INTERVAL {
            return;
        }
        *last = Instant::now();
        bridge::emit("hash.progress", json!({ "hashed": bytes }));
    })
    .await
    .map(|sha256| json!({ "sha256": sha256 }))
    .map_err(|error| error.to_string())
}

fn hash_content(args: &Value) -> Result<FileContent, String> {
    content_from_fields(
        args.get("fd").and_then(Value::as_i64).map(|fd| fd as i32),
        args.string("path").as_deref(),
    )
}

fn parse_spec(args: &Value) -> Result<SendSpec, String> {
    let items = args
        .get("files")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or("files is required and must not be empty")?;
    let files: Vec<FileSpec> = items.iter().map(FileSpec::from_json).collect();
    Ok(SendSpec {
        send_id: spec_send_id(args),
        target: parse_target(args.get("target"))?,
        pin: args.string("pin").filter(|value| !value.is_empty()),
        compute_checksums: args.bool_at("computeChecksums", true),
        timeout: args
            .get("timeoutMs")
            .and_then(Value::as_u64)
            .map(Duration::from_millis),
        files,
    })
}

impl FileSpec {
    fn from_json(value: &Value) -> Self {
        FileSpec {
            id: value.string("id").unwrap_or_default(),
            file_name: value.string("fileName").unwrap_or_default(),
            size: value.u64_at("size", 0),
            file_type: value
                .string("fileType")
                .unwrap_or_else(|| "application/octet-stream".to_string()),
            sha256: value.string("sha256"),
            path: value.string("path"),
            fd: value.get("fd").and_then(Value::as_i64).map(|fd| fd as i32),
            hash_fd: value
                .get("hashFd")
                .and_then(Value::as_i64)
                .map(|fd| fd as i32),
        }
    }

    fn to_dto(&self, sha256: Option<String>) -> FileDto {
        let metadata = self
            .path
            .as_deref()
            .map(Path::new)
            .and_then(FileMetadata::from_path);
        FileDto {
            id: self.id.clone(),
            file_name: self.file_name.clone(),
            size: self.size,
            file_type: self.file_type.clone(),
            sha256,
            preview: None,
            metadata,
        }
    }
}

fn parse_target(value: Option<&Value>) -> Result<Target, String> {
    let object = value
        .and_then(Value::as_object)
        .ok_or("target is required")?;
    let host = map_string(object, "host");
    let port = object.get("port").and_then(Value::as_u64).unwrap_or(53317) as u16;
    let protocol = match map_string(object, "protocol").as_deref() {
        Some("http") => ProtocolType::Http,
        _ => ProtocolType::Https,
    };
    let fingerprint = map_string(object, "fingerprint");
    match (host, fingerprint.clone()) {
        (Some(host), _) => Ok(Target {
            host,
            port,
            protocol,
            fingerprint,
        }),
        // 只给指纹：运行时从 discovery store 挑最优通道
        (None, Some(_)) => Ok(Target {
            host: String::new(),
            port,
            protocol,
            fingerprint,
        }),
        (None, None) => Err("target needs either host or fingerprint".to_string()),
    }
}

fn map_string(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(Value::as_str).map(str::to_string)
}

async fn run_send(
    identity: Arc<Identity>,
    spec: SendSpec,
    token: CancellationToken,
) -> Result<(), String> {
    let target = resolve_target(&spec)?;
    let expected = match target.protocol {
        // HTTPS 下对端身份 = 证书指纹，图钉化；HTTP 模式没有指纹可验
        ProtocolType::Https => target.fingerprint.clone(),
        ProtocolType::Http => None,
    };
    let client = LsHttpClientV2::try_new(
        &identity.key_pem,
        &identity.cert_pem,
        expected,
        spec.timeout,
    )
    .map_err(|error| error.to_string())?;

    let mut files: Vec<(String, FileDto)> = Vec::with_capacity(spec.files.len());
    for file in &spec.files {
        let mut sha256 = file.sha256.clone();
        if sha256.is_none() && spec.compute_checksums {
            sha256 = hash_for_upload(file, &token).await;
            if sha256.is_none() {
                bridge::emit(
                    "send.note",
                    json!({
                        "sendId": spec.send_id, "fileId": file.id,
                        "message": "checksum skipped: no reusable source (pass path or a second hashFd)",
                    }),
                );
            }
        }
        files.push((file.id.clone(), file.to_dto(sha256)));
    }
    let total: u64 = files.iter().map(|(_, dto)| dto.size).sum();
    let map: HashMap<String, FileDto> = files.iter().cloned().collect();

    let prepared = client
        .prepare_upload(
            target.protocol,
            &target.host,
            target.port,
            None,
            PrepareUploadRequestDtoV2 {
                info: identity.register_dto(),
                files: map,
            },
            spec.pin.as_deref(),
            token.clone(),
        )
        .await;

    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(ClientError::StatusCode(status)) => {
            let result = match status.status {
                401 => "pinRequired",
                403 => "declined",
                409 => "recipientBusy",
                429 => "tooManyAttempts",
                _ => "error",
            };
            bridge::emit(
                "send.ended",
                json!({
                    "sendId": spec.send_id, "result": result,
                    "status": status.status, "message": status.message,
                }),
            );
            return Ok(());
        }
        Err(ClientError::Cancelled) => {
            bridge::emit(
                "send.ended",
                json!({ "sendId": spec.send_id, "result": "cancelled" }),
            );
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    };

    // 204：对方一个文件都没接（纯文本消息按已送达处理）
    let Some(response) = prepared.response else {
        bridge::emit(
            "send.ended",
            json!({ "sendId": spec.send_id, "result": "success", "deliveredAsMessage": true }),
        );
        return Ok(());
    };
    let session_id = response.session_id.clone();
    bridge::emit(
        "send.session",
        json!({
            "sendId": spec.send_id, "sessionId": session_id, "status": prepared.status_code,
            "acceptedFileIds": response.files.keys().collect::<Vec<_>>(), "totalBytes": total,
        }),
    );

    let sent = Arc::new(AtomicU64::new(0));
    let mut failures = 0usize;
    // 与 CLI 一致：按文件名排序串行上传，进度是累计字节
    let mut ordered: Vec<FileSpec> = spec
        .files
        .iter()
        .filter(|file| response.files.contains_key(&file.id))
        .cloned()
        .collect();
    ordered.sort_by(|a, b| a.file_name.cmp(&b.file_name));

    for file in ordered {
        let token_for_file = match response.files.get(&file.id) {
            Some(token) => token.clone(),
            None => continue,
        };
        let content = match content_of(&file) {
            Ok(content) => content,
            Err(error) => {
                failures += 1;
                bridge::emit(
                    "send.fileDone",
                    json!({ "sendId": spec.send_id, "sessionId": session_id, "fileId": file.id, "ok": false, "error": error }),
                );
                continue;
            }
        };
        let base = sent.load(Ordering::Relaxed);
        let counter = Arc::clone(&sent);
        let throttle = Arc::new(std::sync::Mutex::new(Instant::now() - PROGRESS_INTERVAL));
        let send_id = spec.send_id.clone();
        let session_for_stream = session_id.clone();
        let file_for_stream = file.id.clone();
        let total_bytes = base + file.size;
        let stream = content.into_stream().map(move |item| {
            if let Ok(bytes) = &item {
                let accumulated = counter.fetch_add(bytes.len() as u64, Ordering::Relaxed) + bytes.len() as u64;
                let mut last = throttle.lock().unwrap();
                if last.elapsed() >= PROGRESS_INTERVAL {
                    *last = Instant::now();
                    bridge::emit(
                        "send.progress",
                        json!({
                            "sendId": send_id, "sessionId": session_for_stream, "fileId": file_for_stream,
                            "sent": accumulated, "total": total_bytes,
                        }),
                    );
                }
            }
            item
        });
        let body = localsend::reqwest::Body::wrap_stream(stream);
        let outcome = client
            .upload(
                target.protocol,
                &target.host,
                target.port,
                None,
                &session_id,
                &file.id,
                &token_for_file,
                body,
                token.clone(),
            )
            .await;
        match outcome {
            Ok(()) => bridge::emit(
                "send.fileDone",
                json!({
                    "sendId": spec.send_id, "sessionId": session_id, "fileId": file.id,
                    "ok": true, "size": file.size,
                }),
            ),
            Err(error) => {
                failures += 1;
                bridge::emit(
                    "send.fileDone",
                    json!({
                        "sendId": spec.send_id, "sessionId": session_id, "fileId": file.id,
                        "ok": false, "error": describe_client_error(&error),
                    }),
                );
            }
        }
    }

    bridge::emit(
        "send.ended",
        json!({
            "sendId": spec.send_id, "sessionId": session_id,
            "result": if failures == 0 { "success" } else { "partial" },
            "failedFiles": failures, "sentBytes": sent.load(Ordering::Relaxed),
        }),
    );
    Ok(())
}

fn resolve_target(spec: &SendSpec) -> Result<Target, String> {
    if !spec.target.host.is_empty() {
        return Ok(Target {
            host: spec.target.host.clone(),
            port: spec.target.port,
            protocol: spec.target.protocol,
            fingerprint: spec.target.fingerprint.clone(),
        });
    }
    let fingerprint = spec
        .target
        .fingerprint
        .as_deref()
        .ok_or("target is incomplete")?;
    let stored =
        state::discovery_slot().and_then(|slot| slot.handle.device_by_fingerprint(fingerprint));
    let stored =
        stored.ok_or_else(|| format!("device {fingerprint} is not discovered; scan first"))?;
    let channel = stored
        .get_best_channel()
        .map(|channel| match channel {
            localsend::discovery::DeviceChannel::Http(http) => http,
        })
        .ok_or("device has no usable channel")?;
    Ok(Target {
        host: channel.host.clone(),
        port: channel.port,
        protocol: channel.protocol,
        fingerprint: Some(fingerprint.to_string()),
    })
}

async fn hash_for_upload(file: &FileSpec, token: &CancellationToken) -> Option<String> {
    let content = content_for_hash(file).ok()?;
    sha256_file_content(content, token, |_| {}).await.ok()
}

fn content_of(file: &FileSpec) -> Result<FileContent, String> {
    content_from_fields(file.fd, file.path.as_deref())
}

/// 哈希要独占一个可读源：fd 读完就到 EOF，不能既算校验和又上传。
fn content_for_hash(file: &FileSpec) -> Result<FileContent, String> {
    match (file.path.as_deref(), file.hash_fd) {
        (Some(path), _) => Ok(FileContent::Path(PathBuf::from(path))),
        (None, Some(fd)) => fd_only(fd),
        (None, None) => Err("file needs path or hashFd to be checksummed".to_string()),
    }
}

#[cfg(target_os = "android")]
fn fd_only(fd: i32) -> Result<FileContent, String> {
    Ok(FileContent::Fd(fd))
}

#[cfg(not(target_os = "android"))]
fn fd_only(_fd: i32) -> Result<FileContent, String> {
    Err("file descriptors are only supported on Android".to_string())
}

fn content_from_fields(fd: Option<i32>, path: Option<&str>) -> Result<FileContent, String> {
    match (fd, path) {
        (Some(_), None) => fd_only(fd.expect("checked")),
        (None, Some(path)) => Ok(FileContent::Path(PathBuf::from(path))),
        _ => Err("exactly one of fd|path is required".to_string()),
    }
}

fn describe_client_error(error: &ClientError) -> String {
    match error {
        ClientError::StatusCode(status) => format!(
            "{};{}",
            status.status,
            status.message.clone().unwrap_or_default()
        ),
        other => other.to_string(),
    }
}

fn spec_send_id(args: &Value) -> String {
    args.string("sendId").unwrap_or_else(fresh_send_id)
}

fn fresh_send_id() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    format!("s-{nanos:x}-{}", SEQ.fetch_add(1, Ordering::Relaxed))
}

impl Clone for FileSpec {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            file_name: self.file_name.clone(),
            size: self.size,
            file_type: self.file_type.clone(),
            sha256: self.sha256.clone(),
            path: self.path.clone(),
            fd: self.fd,
            hash_fd: self.hash_fd,
        }
    }
}
