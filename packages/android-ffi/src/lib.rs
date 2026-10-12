//! JNI entry points for the OneP host app.
//!
//! The ABI is deliberately tiny: three exported symbols and one JSON envelope.
//! Anything that touches tokio is fire-and-forget — [`nativeCall`] validates its argument,
//! hands the work to the runtime and returns `{"ok":true}`; the real result comes back as a
//! `reply` event carrying the same `reqId`. That rule is what keeps the boundary deadlock
//! free: the JNI thread never blocks on Rust, and the Rust pump thread never calls back into
//! `nativeCall`.
//!
//! Panics are caught at the boundary. A panic that unwound through `extern "system"` would
//! abort the process, so every entry point converts one into an `{"code":"panic"}` payload
//! instead.

mod bridge;
mod call;
mod discovery;
mod filename;
mod identity;
#[cfg(test)]
mod loopback;
mod runtime;
mod send;
mod server;
mod state;

use std::panic::AssertUnwindSafe;

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::jstring;

/// Protocol version this crate speaks, straight from core so it cannot drift.
pub(crate) const PROTOCOL_VERSION: &str = localsend::model::discovery::PROTOCOL_VERSION_V2;

/// Cache the [`JavaVM`], keep a global reference to the event sink, start nothing.
///
/// The sink is any object exposing `public void onEvent(String json)`. The method is resolved
/// from the object's own class, so the host is free to rename its package and only has to keep
/// the `onEvent` name — which the OneP consumer rules do. Passing `null` detaches the sink.
///
/// [`nativeCall`]: Java_com_onep_localsend_bridge_LsNative_nativeCall
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_onep_localsend_bridge_LsNative_nativeSetSink<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sink: JObject<'local>,
) {
    let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| bridge::set_sink(&mut env, &sink)));
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => bridge::log(&format!("set_sink rejected: {error}")),
        Err(_) => bridge::log("set_sink panicked"),
    }
}

/// `nativeCall(method: String, json: String): String`
///
/// Returns `{"ok":true}` once the call is accepted, or
/// `{"ok":false,"error":{"code":…,"message":…}}` for argument-level failures. Never blocks.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_onep_localsend_bridge_LsNative_nativeCall<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    method: JString<'local>,
    json: JString<'local>,
) -> jstring {
    let method = take_string(&mut env, &method);
    let payload = take_string(&mut env, &json);
    let out = guarded("call", || call::dispatch(&method, &payload));
    into_jstring(&mut env, out)
}

/// Synchronous pure helpers that must not pay a round trip through the event pump: build info
/// (`op` absent) and filename sanitizing (`op` = `sanitize` / `isValid`). Sanitizing lives here
/// on purpose — the rules come from core and are platform-selected, so reimplementing them in
/// Kotlin would drift.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_onep_localsend_bridge_LsNative_nativeProbe<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    json: JString<'local>,
) -> jstring {
    let payload = take_string(&mut env, &json);
    let out = guarded("probe", || filename::probe(&payload));
    into_jstring(&mut env, out)
}

fn take_string(env: &mut JNIEnv<'_>, value: &JString<'_>) -> String {
    env.get_string(value)
        .map(|borrowed| borrowed.into())
        .unwrap_or_default()
}

fn guarded(label: &str, body: impl FnOnce() -> String) -> String {
    match std::panic::catch_unwind(AssertUnwindSafe(body)) {
        Ok(text) => text,
        Err(_) => {
            eprintln!("[localsend_ffi] {label} panicked across the JNI boundary");
            format!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "error": { "code": "panic", "message": format!("{label} panicked") },
                })
            )
        }
    }
}

fn into_jstring(env: &mut JNIEnv<'_>, text: String) -> jstring {
    match env.new_string(text) {
        // Leaking the local reference is the documented way to hand a string back to Java.
        Ok(string) => string.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
