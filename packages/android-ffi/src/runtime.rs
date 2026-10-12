//! The process-wide tokio runtime.
//!
//! It is created once and never torn down: `OnceLock` cannot be re-armed, and dropping a
//! runtime from inside its own worker threads is not possible anyway. Leaving the OneP
//! partition therefore stops the server and the discovery task (`runtime.shutdown`) but keeps
//! the runtime warm — that is the boundary of the "destroy on leave" behaviour, and the host's
//! README has to say so.

use std::sync::{Mutex, OnceLock};

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
/// 建 runtime 必须串行：并发落败方一旦在 async 上下文里 drop 掉自己那个 Runtime，
/// tokio 会直接 panic（"Cannot drop a runtime in a context where blocking is not allowed"）。
static INIT_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn init(worker_threads: usize) -> Result<usize, String> {
    let threads = worker_threads.clamp(1, 8);
    let _guard = INIT_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.metrics().num_workers());
    }
    let runtime = Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("ls-ffi-worker")
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    // 持锁期间 set 不会失败，因此不存在"落败的 runtime 被 drop"这条路径
    if RUNTIME.set(runtime).is_err() {
        return Err("runtime was initialized concurrently".to_string());
    }
    super::bridge::start_pump();
    Ok(threads)
}

pub(crate) fn started() -> bool {
    RUNTIME.get().is_some()
}

/// 投递到 runtime。异步上下文里用它就够了：runtime 一定在（同步入口已经建好了）。
/// 万一没建（宿主跳过 `runtime.init`），这里只记一条日志，绝不 panic 穿到 JNI 之外。
pub(crate) fn spawn(task: impl std::future::Future<Output = ()> + Send + 'static) {
    match RUNTIME.get() {
        Some(runtime) => {
            runtime.spawn(task);
        }
        None => crate::bridge::log("dropped a task: runtime.init has not been called"),
    }
}

/// 同步入口（JNI 线程）用的版本：runtime 还没建时要当场报错，让宿主拿到明确的 `reply`，
/// 而不是静默丢掉一次调用。
pub(crate) fn try_spawn(
    task: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), String> {
    match RUNTIME.get() {
        Some(runtime) => {
            runtime.spawn(task);
            Ok(())
        }
        None => Err("runtime.init has not been called".to_string()),
    }
}
