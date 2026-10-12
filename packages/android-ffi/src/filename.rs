//! `nativeProbe`: build information and the two synchronous filename helpers.
//!
//! They live on the Rust side because core selects its sanitizing rules per target platform
//! (`Rules::current()` is `Fat` on Android). Reimplementing that in Kotlin is how a host
//! silently diverges from the protocol peer's idea of a legal file name.

use serde_json::{Value, json};

use crate::bridge;

pub(crate) fn probe(payload: &str) -> String {
    let parsed: Value = serde_json::from_str(payload).unwrap_or_else(|_| json!({}));
    let op = parsed.get("op").and_then(Value::as_str).unwrap_or("info");
    let fail = |code: &str, message: &str| {
        json!({ "ok": false, "error": { "code": code, "message": message } }).to_string()
    };
    match op {
        "info" => json!({ "ok": true, "data": bridge::build_info() }).to_string(),
        "sanitize" | "isValid" => match parsed.get("name").and_then(Value::as_str) {
            None => fail("bad_argument", "name is required"),
            Some(name) => {
                let rules = localsend::util::filename::Rules::current();
                if op == "sanitize" {
                    json!({ "ok": true, "name": localsend::util::filename::sanitize(name, rules) })
                        .to_string()
                } else {
                    json!({
                        "ok": true,
                        "valid": localsend::util::filename::is_valid(name, rules),
                    })
                    .to_string()
                }
            }
        },
        other => fail("unknown_op", other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_reports_the_protocol_version() {
        let value: Value = serde_json::from_str(&probe("{}")).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["data"]["protocol"], crate::PROTOCOL_VERSION);
    }

    #[test]
    fn sanitize_replaces_platform_illegal_characters() {
        let value: Value =
            serde_json::from_str(&probe(r#"{"op":"sanitize","name":"a<b:c"}"#)).unwrap();
        // Whatever the host rules are, the illegal ones must be gone.
        assert_eq!(value["ok"], true);
        let name = value["name"].as_str().unwrap();
        assert!(!name.contains('<') && !name.contains(':'));
    }

    #[test]
    fn unknown_op_is_reported_not_panicked() {
        let value: Value = serde_json::from_str(&probe(r#"{"op":"bogus"}"#)).unwrap();
        assert_eq!(value["error"]["code"], "unknown_op");
    }
}
