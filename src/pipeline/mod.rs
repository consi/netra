pub mod window;

use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use window::{FrozenWindow, HISTORY_SIZE, LiveWindow, WINDOW_SECS};

pub use window::attribute_flow_dual;

pub struct WindowManager {
    pub current: ArcSwap<LiveWindow>,
    pub history: ArcSwap<Vec<Arc<FrozenWindow>>>,
    /// Cached snapshot of the current live window, updated every ~1s.
    pub current_snapshot: ArcSwap<FrozenWindow>,
    snapshot_epoch: AtomicU64,
}

impl WindowManager {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let epoch = now / WINDOW_SECS * WINDOW_SECS;
        let empty_frozen = FrozenWindow::empty(epoch);
        Self {
            current: ArcSwap::from_pointee(LiveWindow::new(epoch)),
            history: ArcSwap::from_pointee(Vec::new()),
            current_snapshot: ArcSwap::from_pointee(empty_frozen),
            snapshot_epoch: AtomicU64::new(0),
        }
    }

    /// Rotate: freeze current window, push to history, create new current.
    pub fn rotate(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let new_epoch = now / WINDOW_SECS * WINDOW_SECS;

        let new_window = LiveWindow::new(new_epoch);
        let old = self.current.swap(Arc::new(new_window));

        let frozen = Arc::new(old.freeze());

        let current_history = self.history.load();
        let mut new_history = (**current_history).clone();
        new_history.push(frozen);
        if new_history.len() > HISTORY_SIZE {
            new_history.drain(0..new_history.len() - HISTORY_SIZE);
        }
        self.history.store(Arc::new(new_history));
    }

    /// Refresh the cached snapshot of the current live window (at most once per second).
    pub fn refresh_snapshot(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let last = self.snapshot_epoch.load(Ordering::Relaxed);
        if now <= last {
            return; // already refreshed this second
        }
        self.snapshot_epoch.store(now, Ordering::Relaxed);
        let current = self.current.load();
        self.current_snapshot.store(Arc::new(current.freeze()));
    }
}

/// Spawn the window rotation loop as a tokio task.
pub async fn rotation_loop(manager: Arc<WindowManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(WINDOW_SECS));
    interval.tick().await; // first tick completes immediately
    loop {
        interval.tick().await;
        manager.rotate();
    }
}

/// Spawn the snapshot refresh loop (updates cached freeze every 1s).
pub async fn snapshot_loop(manager: Arc<WindowManager>) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        manager.refresh_snapshot();
    }
}
