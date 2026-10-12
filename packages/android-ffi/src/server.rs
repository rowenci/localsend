//! HTTP server 的启停与应答。
//!
//! core 的模型是「事件带出 oneshot 应答器」，这里把它降级成宿主能用的形状：
//! 事件里只留 id，应答器存进 [`crate::state::ServerSlot`] 的 map，由 `respond*` 兑现。
//! 找不到键就当作已应答过，静默幂等返回 ok——UI 重入不该弹错误。

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use localsend::http::server::common::save::FileUploadTarget;
use localsend::http::server::v2::{PrepareUploadDecisionV2, ServerEventV2};
use localsend::http::server::web::WebConfig;
use localsend::http::server::{ServerConfigV2, ServerHandle, start_with_port};
use localsend::http::state::ClientInfo;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};

use crate::state::ValueExt as _;
use crate::{bridge, discovery, runtime, state};

/// 进度回调节流，与上游 FRB 层一致（20ms），否则宿主会被高频回调打爆
const PROGRESS_INTERVAL: Duration = Duration::from_millis(20);
const EVENT_CHANNEL_CAPACITY: usize = 16;
const STOP_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn start(args: Value) -> Result<Value, String> {
    let identity = state::identity()?;
    // 先停掉遗留实例：分区反复进出时端口不会释放，绑定直接失败（上游 RUNNING_SERVER 同型守卫）
    stop_inner().await;

    let port = args
        .get("port")
        .and_then(Value::as_u64)
        .unwrap_or(identity.port as u64) as u16;
    let pin = args
        .get("pin")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let verify_checksums = args
        .get("verifyChecksums")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let https = args.get("https").and_then(Value::as_bool).unwrap_or(true);

    let info = ClientInfo {
        alias: identity.alias.clone(),
        version: identity.client_info().version,
        device_model: identity.client_info().device_model,
        device_type: Some(identity.device_type.clone()),
        token: identity.fingerprint.clone(),
    };

    let (event_tx, event_rx) = mpsc::channel::<ServerEventV2>(EVENT_CHANNEL_CAPACITY);
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let tls = https.then(|| identity.tls_config());

    let handle: ServerHandle = start_with_port(
        port,
        tls,
        info,
        None,
        Some(ServerConfigV2 {
            pin,
            verify_checksums,
            event_tx,
        }),
        WebConfig::default(),
        stop_rx,
    )
    .await
    .map_err(|error| format!("{error:#}"))?;

    let slot = Arc::new(state::ServerSlot {
        handle,
        stop: std::sync::Mutex::new(Some(stop_tx)),
        decisions: std::sync::Mutex::new(HashMap::new()),
        targets: std::sync::Mutex::new(HashMap::new()),
    });
    let reply = json!({
        "port": slot.handle.port(),
        "addresses": slot.handle.local_addresses().iter().map(|address| address.to_string()).collect::<Vec<_>>(),
    });
    *state::SERVER.lock().unwrap() = Some(slot.clone());
    runtime::spawn(event_loop(slot, event_rx));
    Ok(reply)
}

async fn event_loop(slot: Arc<state::ServerSlot>, mut rx: mpsc::Receiver<ServerEventV2>) {
    while let Some(event) = rx.recv().await {
        match event {
            ServerEventV2::Register { ip, info } => {
                // 对方向我方 register 是设备列表的第二条来源：回喂 discovery store，
                // 否则"别人能看见我、我看不见别人"（cli/src/app/discovery.rs 同一段逻辑）
                discovery::confirm(ip.to_string(), &info);
                bridge::emit(
                    "server.register",
                    json!({ "ip": ip.to_string(), "info": info }),
                );
            }
            ServerEventV2::PrepareUpload {
                session_id,
                ip,
                info,
                cert_fingerprint,
                files,
                decision_tx,
            } => {
                slot.decisions
                    .lock()
                    .unwrap()
                    .insert(session_id.clone(), decision_tx);
                bridge::emit(
                    "server.prepareUpload",
                    json!({
                        "sessionId": session_id,
                        "ip": ip.to_string(),
                        "info": info,
                        "certFingerprint": cert_fingerprint,
                        "files": files,
                    }),
                );
            }
            ServerEventV2::FileUpload {
                session_id,
                file_id,
                file,
                target_tx,
            } => {
                slot.targets
                    .lock()
                    .unwrap()
                    .insert((session_id.clone(), file_id.clone()), target_tx);
                bridge::emit(
                    "server.fileUpload",
                    json!({ "sessionId": session_id, "fileId": file_id, "file": file }),
                );
            }
            ServerEventV2::SessionEnd { session_id, reason } => {
                prune(&slot, &session_id);
                bridge::emit(
                    "server.sessionEnd",
                    json!({ "sessionId": session_id, "reason": format!("{reason:?}") }),
                );
            }
            ServerEventV2::PrepareUploadAborted { session_id } => {
                slot.decisions.lock().unwrap().remove(&session_id);
                bridge::emit(
                    "server.prepareUploadAborted",
                    json!({ "sessionId": session_id }),
                );
            }
            ServerEventV2::CancelReceived { ip, session_id } => {
                bridge::emit(
                    "server.cancelReceived",
                    json!({ "ip": ip.to_string(), "sessionId": session_id }),
                );
            }
            ServerEventV2::ListenerFailed { error } => {
                // socket 被系统作废：宿主要按"探活失败则整体重启 server"处理
                bridge::emit("server.listenerFailed", json!({ "error": error }));
            }
        }
    }
}

fn prune(slot: &state::ServerSlot, session_id: &str) {
    slot.decisions.lock().unwrap().remove(session_id);
    slot.targets
        .lock()
        .unwrap()
        .retain(|(session, _), _| session != session_id);
}

pub async fn stop() -> Value {
    stop_inner().await;
    json!({})
}

async fn stop_inner() {
    let slot = { state::SERVER.lock().unwrap().take() };
    let Some(slot) = slot else { return };
    if let Some(stop_tx) = slot.stop.lock().unwrap().take() {
        let _ = stop_tx.send(());
    }
    // 必须带超时：wait_stopped 在没有干净关停路径时可能永远不返回，端口也就永远占着
    let _ = tokio::time::timeout(STOP_TIMEOUT, slot.handle.wait_stopped()).await;
}

pub fn respond_prepare_upload(args: &Value) -> Result<Value, String> {
    let Some(slot) = state::server_slot() else {
        return Ok(json!({ "alreadyStopped": true })); // 已经停掉了，当作应答过
    };
    let session_id = args.string("sessionId").ok_or("sessionId is required")?;
    let Some(decision_tx) = slot.decisions.lock().unwrap().remove(&session_id) else {
        return Ok(json!({ "alreadyAnswered": true })); // 幂等：重复/迟到的应答不报错
    };
    let decision = match args.string("decision").as_deref() {
        Some("accept") => {
            let ids: HashSet<String> = args
                .get("fileIds")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            PrepareUploadDecisionV2::Accept(ids)
        }
        Some("decline") => PrepareUploadDecisionV2::Decline,
        other => return Err(format!("decision must be accept|decline, got {other:?}")),
    };
    let _ = decision_tx.send(decision);
    Ok(json!({}))
}

pub fn respond_file_upload(args: &Value) -> Result<Value, String> {
    let Some(slot) = state::server_slot() else {
        return Err("server is not running".to_string());
    };
    let session_id = args.string("sessionId").ok_or("sessionId is required")?;
    let file_id = args.string("fileId").ok_or("fileId is required")?;
    let key = (session_id.clone(), file_id.clone());
    let Some(target_tx) = slot.targets.lock().unwrap().remove(&key) else {
        return Ok(json!({ "alreadyAnswered": true })); // 幂等
    };

    let (result_tx, result_rx) = oneshot::channel::<Result<(), String>>();
    let (progress_tx, progress_rx) = mpsc::channel::<u64>(16);
    let session_for_progress = session_id.clone();
    let file_for_progress = file_id.clone();

    // 边收边推进度，终值必发；结果单独发一条 uploadResult（"错误也是事件"）
    runtime::spawn(forward_progress(
        session_for_progress,
        file_for_progress,
        progress_rx,
    ));
    {
        let session_id = session_id.clone();
        let file_id = file_id.clone();
        runtime::spawn(async move {
            let payload = match result_rx.await {
                Ok(Ok(())) => json!({ "sessionId": session_id, "fileId": file_id, "ok": true }),
                Ok(Err(message)) => {
                    json!({ "sessionId": session_id, "fileId": file_id, "ok": false, "error": message })
                }
                Err(_) => json!({
                    "sessionId": session_id, "fileId": file_id, "ok": false,
                    "error": "save target was dropped",
                }),
            };
            bridge::emit("server.uploadResult", payload);
        });
    }

    let target = match (args.get("fd").and_then(Value::as_i64), args.string("path")) {
        #[cfg(target_os = "android")]
        (Some(fd), None) => FileUploadTarget::Fd {
            fd: fd as std::os::fd::RawFd,
            result_tx,
            progress_tx: Some(progress_tx),
        },
        #[cfg(not(target_os = "android"))]
        (Some(_), None) => return Err("file descriptors are only supported on Android".to_string()),
        (None, Some(path)) => FileUploadTarget::Path {
            path: PathBuf::from(path),
            result_tx,
            progress_tx: Some(progress_tx),
        },
        _ => return Err("exactly one of fd|path is required".to_string()),
    };
    let _ = target_tx.send(target);
    Ok(json!({}))
}

pub fn fail_file_upload(args: &Value) -> Result<Value, String> {
    let Some(slot) = state::server_slot() else {
        return Ok(json!({ "alreadyStopped": true }));
    };
    let session_id = args.string("sessionId").ok_or("sessionId is required")?;
    let file_id = args.string("fileId").ok_or("fileId is required")?;
    // 取出即 drop：core 侧这次上传失败（对端拿 500/422），不需要额外信令
    slot.targets.lock().unwrap().remove(&(session_id, file_id));
    Ok(json!({}))
}

pub fn cancel_session(args: &Value) -> Result<Value, String> {
    let Some(slot) = state::server_slot() else {
        return Err("server is not running".to_string());
    };
    let session_id = args.string("sessionId").ok_or("sessionId is required")?;
    let slot = slot.clone();
    let for_task = session_id.clone();
    runtime::spawn(async move {
        if slot.handle.cancel_v2_session(&for_task).await {
            prune(&slot, &for_task);
        }
    });
    Ok(json!({ "sessionId": session_id }))
}

async fn forward_progress(session_id: String, file_id: String, mut rx: mpsc::Receiver<u64>) {
    let mut last = Instant::now() - PROGRESS_INTERVAL;
    let mut written = 0u64;
    while let Some(bytes) = rx.recv().await {
        written = bytes;
        if last.elapsed() < PROGRESS_INTERVAL {
            continue;
        }
        last = Instant::now();
        bridge::emit(
            "server.uploadProgress",
            json!({ "sessionId": session_id, "fileId": file_id, "received": written }),
        );
    }
    bridge::emit(
        "server.uploadProgress",
        json!({ "sessionId": session_id, "fileId": file_id, "received": written, "final": true }),
    );
}
