//! Shared application state: the persistent device inventory behind a mutex.

use std::sync::Mutex;

use hlu_core::{Store, paths};

/// State managed by Tauri and shared across command invocations.
pub struct AppState {
    /// The SQLite-backed inventory. A `Mutex` makes the (non-`Sync`) connection shareable; all
    /// store operations are short and synchronous, never held across an `.await`.
    pub store: Mutex<Store>,
}

impl AppState {
    /// Open the on-disk store, falling back to an in-memory store if the data directory is
    /// unavailable (so the app still runs, just without persistence).
    pub fn new() -> Self {
        let store = paths::default_db_path()
            .and_then(|path| Store::open(&path))
            .unwrap_or_else(|err| {
                tracing::warn!("using in-memory store (no persistence): {err}");
                Store::open_in_memory().expect("in-memory store should always open")
            });
        Self {
            store: Mutex::new(store),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}
