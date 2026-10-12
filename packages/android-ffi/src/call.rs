//! `nativeCall` 的方法分发。
//!
//! 两条失败通道，刻意不混：
//! - 参数级失败（unknown_method / bad_json / 缺参数）同步返回 `{"ok":false,…}`，**不产生**
//!   reply 事件；
//! - 执行级失败以 `reply{ok:false}` 送达（此时调用已被受理，同步返回值只表示"收到"）。

use serde_json::{Value, json};

use crate::state::ValueExt as _;
use crate::{bridge, discovery, identity, runtime, send, server};

pub(crate) fn dispatch(method: &str, payload: &str) -> String {
    let parsed: Value = match serde_json::from_str(payload) {
        Ok(parsed) => parsed,
        Err(error) => {
            return error_json("bad_json", &format!("payload is not valid JSON: {error}"));
        }
    };
    let req_id = parsed.string("reqId");
    match handle(method, parsed, req_id) {
        Accepted::Sync | Accepted::Async => ok_json(),
        Accepted::Rejected(code, message) => error_json(&code, &message),
    }
}

enum Accepted {
    /// 结果已就绪，reply 已在本模块发出。
    Sync,
    /// 已受理，reply 由被 spawn 的任务发。
    Async,
    /// 受理前就被拒：同步返回，不发 reply。
    Rejected(String, String),
}

fn handle(method: &str, args: Value, req_id: Option<String>) -> Accepted {
    match method {
        "runtime.init" => match runtime::init(args.u64_at("workerThreads", 2) as usize) {
            Ok(threads) => reply_now(req_id, json!({ "workerThreads": threads })),
            Err(message) => Accepted::Rejected("runtime_init_failed".to_string(), message),
        },

        "runtime.shutdown" => spawn(req_id, shutdown_all()),

        "identity.load" => match identity::config_from(&args) {
            Ok(config) => spawn(req_id, async move { identity::load(config).await }),
            Err(error) => Accepted::Rejected("bad_argument".to_string(), error),
        },

        "server.start" => spawn(req_id, server::start(args)),
        "server.stop" => spawn(req_id, async { Ok(server::stop().await) }),
        "server.respondPrepareUpload" => {
            sync_respond(server::respond_prepare_upload(&args), req_id)
        }
        "server.respondFileUpload" => sync_respond(server::respond_file_upload(&args), req_id),
        "server.failFileUpload" => sync_respond(server::fail_file_upload(&args), req_id),
        "server.cancelSession" => sync_respond(server::cancel_session(&args), req_id),

        "discovery.start" => spawn(req_id, discovery::start(args)),
        "discovery.stop" => spawn(req_id, async { Ok(discovery::stop().await) }),
        "discovery.announce" => spawn(req_id, discovery::announce()),
        "discovery.discoverStaged" => {
            let args = args.clone();
            spawn(
                req_id,
                async move { discovery::discover_staged(&args).await },
            );
            Accepted::Async
        }
        "discovery.addDevice" => sync_respond(discovery::add_device(&args), req_id),
        "discovery.devices" => sync_respond(discovery::devices(), req_id),
        "discovery.deviceByFingerprint" => match args.string("fingerprint") {
            Some(fingerprint) => reply_now(req_id, discovery::device_by_fingerprint(&fingerprint)),
            None => Accepted::Rejected(
                "bad_argument".to_string(),
                "fingerprint is required".to_string(),
            ),
        },

        "send.start" => match send::start(&args) {
            Ok(data) => reply_now(req_id, data),
            Err(error) => Accepted::Rejected("bad_argument".to_string(), error),
        },
        "send.cancel" => match send::cancel(&args) {
            Ok(data) => reply_now(req_id, data),
            Err(error) => Accepted::Rejected("bad_argument".to_string(), error),
        },
        "hash.file" => {
            if let Err(error) = send::validate_hash(&args) {
                return Accepted::Rejected("bad_argument".to_string(), error);
            }
            spawn(req_id, send::hash_file(args))
        }

        other => Accepted::Rejected(
            "unknown_method".to_string(),
            format!("{other} is not implemented by this build of liblocalsend_ffi"),
        ),
    }
}

fn sync_respond(result: Result<Value, String>, req_id: Option<String>) -> Accepted {
    match result {
        Ok(data) => reply_now(req_id, data),
        Err(message) => Accepted::Rejected("call_failed".to_string(), message),
    }
}

fn reply_now(req_id: Option<String>, data: Value) -> Accepted {
    bridge::emit_reply(req_id.as_deref(), data);
    Accepted::Sync
}

/// 同步入口一律用 [`runtime::spawn`]：JNI 线程上没有"当前 runtime"，
/// 直接 `tokio::spawn` 会 panic（真机第一次跑就撞上了，主机 #[tokio::test] 反而盖不住）。
fn spawn<F>(req_id: Option<String>, work: F) -> Accepted
where
    F: std::future::Future<Output = Result<Value, String>> + Send + 'static,
{
    match runtime::try_spawn(async move {
        match work.await {
            Ok(data) => bridge::emit_reply(req_id.as_deref(), data),
            Err(message) => bridge::emit_reply_error(req_id.as_deref(), "call_failed", &message),
        }
    }) {
        Ok(()) => Accepted::Async,
        Err(message) => Accepted::Rejected("runtime_not_started".to_string(), message),
    }
}

async fn shutdown_all() -> Result<Value, String> {
    server::stop().await;
    discovery::stop().await;
    // runtime 本身留着：OnceLock 不可重建，见 runtime.rs
    Ok(json!({ "runtimeRetained": true }))
}

fn ok_json() -> String {
    json!({ "ok": true }).to_string()
}

fn error_json(code: &str, message: &str) -> String {
    json!({ "ok": false, "error": { "code": code, "message": message } }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(method: &str, payload: &str) -> Value {
        serde_json::from_str(&dispatch(method, payload)).unwrap()
    }

    #[test]
    fn unknown_method_is_refused_synchronously() {
        let value = call("nope.does_not_exist", "{}");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "unknown_method");
    }

    #[test]
    fn unparsable_payload_is_refused() {
        assert_eq!(
            call("runtime.init", "not json")["error"]["code"],
            "bad_json"
        );
    }

    #[test]
    fn argument_errors_are_visible_without_a_round_trip() {
        let value = call("identity.load", "{}");
        assert_eq!(value["error"]["code"], "bad_argument");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("dataDir")
        );
        // 纯同步方法在身份/发现未就绪时当场报 call_failed，不会静默成功
        assert_eq!(
            call("discovery.devices", "{}")["error"]["code"],
            "call_failed"
        );
    }

    #[test]
    fn send_start_validates_before_accepting() {
        let value = call("send.start", r#"{"files":[]}"#);
        assert_eq!(value["error"]["code"], "bad_argument");
        assert!(
            value["error"]["message"]
                .as_str()
                .unwrap()
                .contains("files")
        );
    }

    #[test]
    fn init_is_idempotent_and_reports_workers() {
        assert_eq!(call("runtime.init", r#"{"workerThreads":2}"#)["ok"], true);
        assert_eq!(call("runtime.init", "{}")["ok"], true);
        assert!(runtime::started());
    }
}
