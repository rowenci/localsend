//! The process-wide tokio runtime.
//!
//! It is created once and never torn down: `OnceLock` cannot be re-armed, and dropping a
//! runtime from inside its own worker threads is not possible anyway. Leaving the OneP
//! partition therefore stops the server and the discovery task (`runtime.shutdown`) but keeps
//! the runtime warm — that is the boundary of the "destroy on leave" behaviour, and the host's
//! README has to say so.

use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub(crate) fn init(worker_threads: usize) -> Result<usize, String> {
    let threads = worker_threads.clamp(1, 8);
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime.metrics().num_workers());
    }
    let runtime = Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("ls-ffi-worker")
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    // A losing race is fine: the winner's runtime is the one that stays.
    let _ = RUNTIME.set(runtime);
    super::bridge::start_pump();
    Ok(RUNTIME
        .get()
        .map(|runtime| runtime.metrics().num_workers())
        .unwrap_or(threads))
}

pub(crate) fn started() -> bool {
    RUNTIME.get().is_some()
}

/// Spawn onto the runtime. Returns an error instead of panicking when `runtime.init` was never
/// called, which is the state a host that skipped initialization lands in.
#[allow(dead_code)] // M1 起所有会碰 tokio 的方法都经由它下发
pub(crate) fn spawn(
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
