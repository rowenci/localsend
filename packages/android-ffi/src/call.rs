//! Method dispatch for `nativeCall`.
//!
//! Two failure channels, deliberately not mixed:
//! - argument-level failures (unknown method, unparsable payload, runtime not started) are
//!   returned synchronously as `{"ok":false,…}` and produce **no** `reply` event,
//! - execution failures come back asynchronously as a `reply` with `ok:false` and the caller's
//!   `reqId`, because by then the call has already been accepted.

use serde_json::{Value, json};

use crate::{bridge, runtime};

/// Methods that arrive with M1 (identity/server/discovery/send/hash). Listed here so a host
/// build against an older `.so` gets `not_implemented` instead of a confusing `unknown_method`.
const NOT_IMPLEMENTED: &[&str] = &[
    "identity.load",
    "server.start",
    "server.stop",
    "server.respondPrepareUpload",
    "server.respondFileUpload",
    "server.failFileUpload",
    "discovery.start",
    "discovery.stop",
    "discovery.announce",
    "discovery.discoverStaged",
    "discovery.addDevice",
    "discovery.devices",
    "discovery.deviceByFingerprint",
    "discovery.setChannelStatus",
    "send.start",
    "send.cancel",
    "hash.file",
];

enum Accepted {
    /// Handled synchronously; this is the raw return value of `nativeCall`.
    Immediate(String),
    /// Queued: `{"ok":true}` now, the result as a `reply` event later.
    Queued,
    /// Refused before queueing: returned synchronously.
    Rejected(String, String),
}

pub(crate) fn dispatch(method: &str, payload: &str) -> String {
    let parsed: Value = match serde_json::from_str(payload) {
        Ok(parsed) => parsed,
        Err(error) => {
            return error_json("bad_json", &format!("payload is not valid JSON: {error}"));
        }
    };
    let req_id = parsed
        .get("reqId")
        .and_then(Value::as_str)
        .map(str::to_string);
    match handle(method, &parsed, req_id.as_deref()) {
        Accepted::Immediate(text) => text,
        Accepted::Queued => ok_json(),
        Accepted::Rejected(code, message) => error_json(&code, &message),
    }
}

fn handle(method: &str, args: &Value, req_id: Option<&str>) -> Accepted {
    match method {
        "runtime.init" => match runtime::init(number(args, "workerThreads", 2)) {
            Ok(threads) => {
                bridge::emit_reply(req_id, json!({ "workerThreads": threads }));
                Accepted::Queued
            }
            Err(message) => Accepted::Rejected("runtime_init_failed".to_string(), message),
        },
        // Server and discovery teardown lands with M1; the runtime itself stays (see runtime.rs).
        "runtime.shutdown" => {
            bridge::emit_reply(req_id, json!({ "runtimeRetained": true }));
            Accepted::Queued
        }
        "runtime.probe" => Accepted::Immediate(
            json!({ "ok": true, "data": { "runtimeStarted": runtime::started() } }).to_string(),
        ),
        other if NOT_IMPLEMENTED.contains(&other) => {
            Accepted::Rejected("not_implemented".to_string(), other.to_string())
        }
        other => Accepted::Rejected("unknown_method".to_string(), other.to_string()),
    }
}

fn number(args: &Value, key: &str, fallback: usize) -> usize {
    args.get(key)
        .and_then(Value::as_u64)
        .unwrap_or(fallback as u64) as usize
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

    #[test]
    fn unknown_method_is_refused_synchronously() {
        let text = dispatch("nope.does_not_exist", "{}");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"]["code"], "unknown_method");
    }

    #[test]
    fn unparsable_payload_is_refused() {
        let text = dispatch("runtime.init", "not json");
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["error"]["code"], "bad_json");
    }

    #[test]
    fn planned_methods_report_not_implemented_until_m1() {
        let value: Value = serde_json::from_str(&dispatch("server.start", "{}")).unwrap();
        assert_eq!(value["error"]["code"], "not_implemented");
    }

    #[test]
    fn init_returns_accepted_and_replies_through_the_pump() {
        // No JVM in tests: the reply is dropped by the pump-less emit, but the contract above
        // still has to hold — accepted, and no synchronous error body.
        let value: Value =
            serde_json::from_str(&dispatch("runtime.init", r#"{"reqId":"r-1"}"#)).unwrap();
        assert_eq!(value["ok"], true);
        assert!(runtime::started());
        // Second call is idempotent and reports the same worker count.
        let again: Value = serde_json::from_str(&dispatch("runtime.init", "{}")).unwrap();
        assert_eq!(again["ok"], true);
    }
}
