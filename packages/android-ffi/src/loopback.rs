//! 同机回环集成测试：用真实的 HTTPS/mTLS 走完一次发送—应答—落盘。
//!
//! 它验证的是**这层胶水**而不是 core：`send.start` 的 prepare 分派、`server.prepareUpload`
//! 事件带出的 oneshot 是否真被 `respondPrepareUpload` 兑现、`respondFileUpload` 给出的
//! 保存目标是否被 core 写入、`send.ended` 的终态是否正确。没有 JVM 时事件落在
//! [`bridge::TEST_EVENTS`]，测试按类型取走。

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::{bridge, call, runtime};

fn call_sync(method: &str, payload: Value) -> Value {
    let text = call::dispatch(method, &payload.to_string());
    let ack: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{method} ack not JSON: {text} ({error})"));
    assert_eq!(ack["ok"], json!(true), "{method} rejected: {ack}");
    ack
}

async fn wait_event(kind: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let found = {
            let mut events = bridge::TEST_EVENTS.lock().unwrap();
            events
                .iter()
                .position(|event| event["type"] == kind)
                .map(|index| events.remove(index))
        };
        if let Some(event) = found {
            return event["data"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for a {kind} event"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_reply(req_id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let found = {
            let mut events = bridge::TEST_EVENTS.lock().unwrap();
            events
                .iter()
                .position(|event| {
                    event["type"] == "reply" && event["data"]["reqId"] == json!(req_id)
                })
                .map(|index| events.remove(index))
        };
        if let Some(event) = found {
            let data = &event["data"];
            assert_eq!(data["ok"], json!(true), "reply for {req_id} failed: {data}");
            return data["data"].clone();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for the reply to {req_id}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// 这些测试碰的是进程级全局（IDENTITY / SERVER / DISCOVERY），并行跑会互相踩：
/// 一个测试的 identity.load 会把另一个正在用的身份换掉。用一把锁把它们排开。
static GLOBALS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_globals() -> std::sync::MutexGuard<'static, ()> {
    GLOBALS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("ls-ffi-{tag}-{nanos:x}"));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[tokio::test]
// 测试里跨 await 持有这把 std 锁是安全的：#[tokio::test] 是单线程 runtime，
// 两个测试只靠它排队，不会真的把 worker 线程堵死。
#[allow(clippy::await_holding_lock)]
async fn loopback_transfer_accept_and_decline() {
    let _globals = lock_globals();
    // 全局槽位（SERVER/IDENTITY）是进程级的，两个场景必须顺序跑
    accept_case().await;
    decline_case().await;
}

async fn accept_case() {
    runtime::init(2).unwrap();
    let dir = temp_dir("loopback");

    let identity = {
        call_sync(
            "identity.load",
            json!({ "reqId": "r-identity", "dataDir": dir.display().to_string(), "alias": "FFI-Test", "port": 54321 }),
        );
        wait_reply("r-identity").await
    };
    let fingerprint = identity["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(
        fingerprint.len(),
        64,
        "fingerprint should be a 64-char uppercase hex digest"
    );

    let port = {
        call_sync(
            "server.start",
            json!({ "reqId": "r-server", "port": 54321, "https": true, "verifyChecksums": true }),
        );
        wait_reply("r-server").await
    }["port"]
        .as_u64()
        .unwrap();

    let payload: Vec<u8> = (0..4096).map(|index| (index % 251) as u8).collect();
    let source = dir.join("payload.bin");
    std::fs::write(&source, &payload).unwrap();
    let destination = dir.join("received.bin");

    call_sync(
        "send.start",
        json!({
            "reqId": "r-send",
            "sendId": "s-1",
            "computeChecksums": false,
            "target": { "host": "127.0.0.1", "port": port, "protocol": "https", "fingerprint": fingerprint },
            "files": [{
                "id": "f-1",
                "fileName": "payload.bin",
                "size": payload.len(),
                "fileType": "application/octet-stream",
                "path": source.display().to_string(),
            }],
        }),
    );
    assert_eq!(wait_reply("r-send").await["sendId"], json!("s-1"));

    let pending = wait_event("server.prepareUpload").await;
    let session_id = pending["sessionId"].as_str().unwrap().to_string();
    assert_eq!(pending["files"]["f-1"]["fileName"], json!("payload.bin"));
    // 对端身份取证书指纹，不是自报的 fingerprint 字段
    assert_eq!(pending["certFingerprint"].as_str().unwrap(), fingerprint);

    call_sync(
        "server.respondPrepareUpload",
        json!({ "reqId": "r-decision", "sessionId": session_id, "decision": "accept", "fileIds": ["f-1"] }),
    );
    wait_reply("r-decision").await;

    let upload = wait_event("server.fileUpload").await;
    assert_eq!(upload["sessionId"], json!(session_id));
    call_sync(
        "server.respondFileUpload",
        json!({
            "reqId": "r-target",
            "sessionId": session_id,
            "fileId": "f-1",
            "path": destination.display().to_string(),
        }),
    );
    wait_reply("r-target").await;

    let result = wait_event("server.uploadResult").await;
    assert_eq!(
        result["ok"],
        json!(true),
        "server-side save failed: {result}"
    );

    let ended = wait_event("send.ended").await;
    assert_eq!(
        ended["result"],
        json!("success"),
        "send did not finish cleanly: {ended}"
    );
    assert_eq!(ended["sendId"], json!("s-1"));

    assert_eq!(
        std::fs::read(&destination).unwrap(),
        payload,
        "received bytes differ from sent bytes"
    );

    call_sync("runtime.shutdown", json!({ "reqId": "r-shutdown" }));
    wait_reply("r-shutdown").await;
    let _ = std::fs::remove_dir_all(&dir);
}

async fn decline_case() {
    runtime::init(2).unwrap();
    let dir = temp_dir("decline");
    call_sync(
        "identity.load",
        json!({ "reqId": "d-identity", "dataDir": dir.display().to_string(), "alias": "FFI-Test", "port": 54322 }),
    );
    let fingerprint = wait_reply("d-identity").await["fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    call_sync(
        "server.start",
        json!({ "reqId": "d-server", "port": 54322, "https": true }),
    );
    wait_reply("d-server").await;

    let source = dir.join("note.txt");
    std::fs::write(&source, b"decline me").unwrap();
    let destination = dir.join("should-not-exist.txt");

    call_sync(
        "send.start",
        json!({
            "reqId": "d-send",
            "sendId": "s-decline",
            "computeChecksums": false,
            "target": { "host": "127.0.0.1", "port": 54322, "protocol": "https", "fingerprint": fingerprint },
            "files": [{ "id": "x", "fileName": "note.txt", "size": 10, "fileType": "text/plain", "path": source.display().to_string() }],
        }),
    );
    wait_reply("d-send").await;
    let pending = wait_event("server.prepareUpload").await;
    call_sync(
        "server.respondPrepareUpload",
        json!({ "reqId": "d-decline", "sessionId": pending["sessionId"], "decision": "decline" }),
    );
    wait_reply("d-decline").await;

    let ended = wait_event("send.ended").await;
    assert_eq!(
        ended["result"],
        json!("declined"),
        "sender should learn the peer declined: {ended}"
    );
    assert_eq!(ended["status"], json!(403));
    assert!(
        !destination.exists(),
        "a declined session must not write anything"
    );

    call_sync("runtime.shutdown", json!({ "reqId": "d-shutdown" }));
    wait_reply("d-shutdown").await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// 真机上 `nativeCall` 跑在宿主的 `ls-native` 线程，那里没有"当前 tokio runtime"。
/// 早先用 `tokio::spawn` 的版本会当场 panic（设备上第一次点自检就炸了），而
/// `#[tokio::test]` 自带 runtime，恰好把这个盲区盖住 —— 这条测试专门补上。
#[test]
fn dispatch_survives_a_thread_without_a_runtime() {
    let dir = temp_dir("off-runtime");
    let _globals = lock_globals();
    let payload = json!({
        "reqId": "off-1",
        "dataDir": dir.display().to_string(),
        "alias": "OffRuntime",
        "port": 54401,
    });
    let worker = std::thread::spawn(move || {
        let init: Value =
            serde_json::from_str(&call::dispatch("runtime.init", r#"{"workerThreads": 1}"#))
                .unwrap();
        assert_eq!(init["ok"], json!(true), "runtime.init ack: {init}");
        let ack: Value =
            serde_json::from_str(&call::dispatch("identity.load", &payload.to_string())).unwrap();
        assert_eq!(
            ack["ok"],
            json!(true),
            "identity.load must be accepted off-runtime: {ack}"
        );
        // reply 由 runtime 上的任务发出，这里用阻塞轮询等（没有 async 上下文可用）
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let found = {
                let mut events = bridge::TEST_EVENTS.lock().unwrap();
                events
                    .iter()
                    .position(|event| {
                        event["type"] == "reply" && event["data"]["reqId"] == json!("off-1")
                    })
                    .map(|index| events.remove(index))
            };
            if let Some(event) = found {
                let data = &event["data"];
                assert_eq!(
                    data["ok"],
                    json!(true),
                    "identity.load reply failed: {data}"
                );
                assert_eq!(data["data"]["fingerprint"].as_str().unwrap().len(), 64);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "no reply from the off-runtime call"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    assert!(
        worker.join().is_ok(),
        "dispatch panicked off the tokio context"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
