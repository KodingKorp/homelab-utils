//! Resolution of per-platform application data locations.

use crate::error::{CoreError, Result};
use directories::ProjectDirs;
use std::path::PathBuf;

/// Reverse-DNS qualifier / organization / application used for data dirs.
const QUALIFIER: &str = "dev";
const ORGANIZATION: &str = "KodingKorp";
const APPLICATION: &str = "homelab-utils";

/// Platform-appropriate project directories (e.g. `%APPDATA%\KodingKorp\homelab-utils` on
/// Windows, `~/.local/share/homelab-utils` on Linux).
pub fn project_dirs() -> Result<ProjectDirs> {
    ProjectDirs::from(QUALIFIER, ORGANIZATION, APPLICATION).ok_or(CoreError::NoDataDir)
}

/// Default path for the SQLite working store.
pub fn default_db_path() -> Result<PathBuf> {
    Ok(project_dirs()?.data_dir().join("inventory.db"))
}

/// Default path for the human-readable JSON export.
pub fn default_export_path() -> Result<PathBuf> {
    Ok(project_dirs()?.data_dir().join("inventory.json"))
}
