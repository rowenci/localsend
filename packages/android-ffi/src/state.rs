//! 进程内的全局槽位：身份、server、discovery、取消令牌。
//!
//! 应答用的 `oneshot::Sender` 跨不了 FFI 边界，所以全部留在 Rust 侧，宿主只拿到
//! `sessionId` / `fileId` 和一组 `respond*` 方法（照搬上游 FRB 层的做法）。
//! 找不到键就当作已应答过，静默幂等返回 ok —— UI 重入不该弹错误。

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use localsend::discovery::DiscoveryHandle;
use localsend::http::server::ServerHandle;
use localsend::http::server::common::save::FileUploadTarget;
use localsend::http::server::v2::PrepareUploadDecisionV2;
use serde_json::Value;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::identity::Identity;

/// 一个运行中的 HTTP server 与它欠下的应答。
pub struct ServerSlot {
    pub handle: ServerHandle,
    pub stop: Mutex<Option<oneshot::Sender<()>>>,
    /// key = sessionId（core 同一时刻只允许一个上传会话，但按 id 存更保险）
    pub decisions: Mutex<HashMap<String, oneshot::Sender<PrepareUploadDecisionV2>>>,
    /// key = (sessionId, fileId)
    pub targets: Mutex<HashMap<(String, String), oneshot::Sender<FileUploadTarget>>>,
}

pub struct DiscoverySlot {
    pub handle: DiscoveryHandle,
    pub stop: Mutex<Option<oneshot::Sender<()>>>,
}

pub static IDENTITY: LazyLock<Mutex<Option<Arc<Identity>>>> = LazyLock::new(|| Mutex::new(None));
pub static SERVER: LazyLock<Mutex<Option<Arc<ServerSlot>>>> = LazyLock::new(|| Mutex::new(None));
pub static DISCOVERY: LazyLock<Mutex<Option<Arc<DiscoverySlot>>>> =
    LazyLock::new(|| Mutex::new(None));
/// key = 宿主给的 sendId（prepare 还没回来时也要能取消，所以不能等服务端的 sessionId）
pub static TOKENS: LazyLock<Mutex<HashMap<String, CancellationToken>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

pub fn identity() -> Result<Arc<Identity>, String> {
    IDENTITY
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "identity.load has not been called".to_string())
}

pub fn set_identity(identity: Arc<Identity>) {
    *IDENTITY.lock().unwrap() = Some(identity);
}

pub fn server_slot() -> Option<Arc<ServerSlot>> {
    SERVER.lock().unwrap().clone()
}

pub fn discovery_slot() -> Option<Arc<DiscoverySlot>> {
    DISCOVERY.lock().unwrap().clone()
}

pub fn register_token(key: &str, token: CancellationToken) {
    TOKENS.lock().unwrap().insert(key.to_string(), token);
}

pub fn cancel_token(key: &str) {
    if let Some(token) = TOKENS.lock().unwrap().remove(key) {
        token.cancel();
    }
}

pub fn forget_token(key: &str) {
    TOKENS.lock().unwrap().remove(key);
}

/// 读一个字符串字段（多处要用，集中一处免得每个模块自己长一遍）
pub trait ValueExt {
    fn string(&self, key: &str) -> Option<String>;
    fn u64_at(&self, key: &str, fallback: u64) -> u64;
    fn bool_at(&self, key: &str, fallback: bool) -> bool;
}

impl ValueExt for Value {
    fn string(&self, key: &str) -> Option<String> {
        self.get(key).and_then(Value::as_str).map(str::to_string)
    }

    fn u64_at(&self, key: &str, fallback: u64) -> u64 {
        self.get(key).and_then(Value::as_u64).unwrap_or(fallback)
    }

    fn bool_at(&self, key: &str, fallback: bool) -> bool {
        self.get(key).and_then(Value::as_bool).unwrap_or(fallback)
    }
}
