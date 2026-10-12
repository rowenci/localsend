//! The Rust→Java side of the boundary: one sink, one pump thread, one JSON event per callback.
//!
//! Thread rules (they are the whole reason the pump exists):
//! - tokio worker threads only ever `emit()` into the channel; they never touch JNI,
//! - exactly one OS thread is attached to the JVM and does all `CallObjectMethod` work,
//! - that thread never calls back into Rust entry points, so no re-entrant lock ordering
//!   can form.

use std::sync::{Mutex, OnceLock};

use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use serde_json::{Value, json};
use tokio::sync::mpsc;

use crate::PROTOCOL_VERSION;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static SINK: Mutex<Option<GlobalRef>> = Mutex::new(None);
static PUMP: OnceLock<mpsc::UnboundedSender<Value>> = OnceLock::new();

/// Sequence number carried by every event, so the host can spot a lost or reordered callback.
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 主机集成测试的事件副本（没有 JVM 时 `emit` 无处可送，测试靠它等事件）。
#[cfg(test)]
pub static TEST_EVENTS: std::sync::LazyLock<std::sync::Mutex<Vec<Value>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

pub(crate) fn set_sink(env: &mut JNIEnv<'_>, sink: &JObject<'_>) -> Result<(), String> {
    if sink.is_null() {
        *SINK.lock().unwrap() = None;
        return Ok(());
    }
    let global = env.new_global_ref(sink).map_err(|e| e.to_string())?;
    // The JavaVM handle is process-wide and interchangeable, so the first caller wins.
    let _ = JAVA_VM.set(env.get_java_vm().map_err(|e| e.to_string())?);
    *SINK.lock().unwrap() = Some(global);
    Ok(())
}

/// Start the pump thread. Idempotent; called from `runtime.init`.
pub(crate) fn start_pump() {
    PUMP.get_or_init(|| {
        let (tx, mut rx) = mpsc::unbounded_channel::<Value>();
        if std::thread::Builder::new()
            .name("ls-ffi-pump".to_string())
            .spawn(move || pump_loop(&mut rx))
            .is_err()
        {
            eprintln!("[localsend_ffi] could not spawn the pump thread");
        }
        tx
    });
}

fn pump_loop(rx: &mut mpsc::UnboundedReceiver<Value>) {
    let Some(vm) = JAVA_VM.get() else {
        // 没有 JVM（主机测试路径）：照样把通道消费干净，emit 因此永远不会因为没人收而阻塞。
        // 真机上 set_sink 总在 runtime.init 之前，不会走到这里。
        eprintln!("[localsend_ffi] pump has no JavaVM, draining events without delivering");
        while rx.blocking_recv().is_some() {}
        return;
    };
    let mut attached = match vm.attach_current_thread() {
        Ok(attached) => attached,
        Err(error) => {
            eprintln!("[localsend_ffi] pump stopped: {error}");
            return;
        }
    };

    let mut failures = 0u32;
    while let Some(event) = rx.blocking_recv() {
        let text = event.to_string();
        let Ok(java_text) = attached.new_string(text) else {
            failures += 1;
            continue;
        };
        let args = [JValue::Object(&java_text)];
        let mut sink_guard = SINK.lock().unwrap();
        let Some(sink) = sink_guard.as_mut() else {
            // Detached on purpose (runtime.shutdown): drop events instead of stalling the pump.
            continue;
        };
        match attached.call_method(sink.as_obj(), "onEvent", "(Ljava/lang/String;)V", &args) {
            Ok(value) => {
                let _ = value;
            }
            Err(error) => {
                failures += 1;
                eprintln!("[localsend_ffi] onEvent failed: {error}");
                let _ = attached.exception_clear();
            }
        }
        drop(sink_guard);
        if failures >= 32 {
            eprintln!("[localsend_ffi] pump giving up after {failures} callback failures");
            return;
        }
    }
}

/// Push one event to the host. Unbounded on purpose: control events (`reply`, `prepareUpload`)
/// must never be dropped, unlike core's own `try_send` channels, which are allowed to lose
/// discovery noise because the store keeps the truth.
pub(crate) fn emit(kind: &str, data: Value) {
    let event = json!({
        "type": kind,
        "seq": SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        "data": data,
    });
    // 主机测试没有 JVM，事件在这里留一份副本供测试按类型取走
    #[cfg(test)]
    TEST_EVENTS.lock().unwrap().push(event.clone());
    if let Some(tx) = PUMP.get() {
        let _ = tx.send(event);
    }
}

pub(crate) fn emit_reply(req_id: Option<&str>, data: Value) {
    if let Some(req_id) = req_id {
        emit(
            "reply",
            json!({ "reqId": req_id, "ok": true, "data": data }),
        );
    }
}

#[allow(dead_code)] // 与 detach_sink 一起在 M1 接线（异步执行失败要回 reply 而不是同步报错）
pub(crate) fn emit_reply_error(req_id: Option<&str>, code: &str, message: &str) {
    if let Some(req_id) = req_id {
        emit(
            "reply",
            json!({
                "reqId": req_id,
                "ok": false,
                "error": { "code": code, "message": message },
            }),
        );
    }
}

pub(crate) fn log(message: &str) {
    eprintln!("[localsend_ffi] {message}");
    emit("log", json!({ "level": "info", "text": message }));
}

/// Used by `runtime.shutdown` (M1) and by tests that need a quiet pump.
#[allow(dead_code)]
pub(crate) fn detach_sink() {
    if let Ok(mut sink) = SINK.lock() {
        *sink = None;
    }
}

/// Build information the host shows in its about page and uses to detect a stale artifact.
pub(crate) fn build_info() -> Value {
    json!({
        "ffi": concat!("localsend-android-ffi ", env!("CARGO_PKG_VERSION")),
        "protocol": PROTOCOL_VERSION,
        "runtimeStarted": crate::runtime::started(),
        "pumpStarted": PUMP.get().is_some(),
    })
}
