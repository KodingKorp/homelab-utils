//! Error type shared across homelab-utils crates.

use thiserror::Error;

/// Errors produced by the core domain and persistence layer.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A SQLite / persistence failure.
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    /// JSON (de)serialization failure for import/export.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Filesystem failure while reading/writing the store or exports.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The platform did not yield a usable application data directory.
    #[error("could not determine an application data directory")]
    NoDataDir,
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, CoreError>;
