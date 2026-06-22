//! Shared domain model and persistence for **homelab-utils**.
//!
//! This crate is intentionally GUI-free and dependency-light so it can be linked by both the
//! desktop app and the lightweight CLI/daemon binaries without pulling in any UI tree.
//!
//! - [`model`] — the persistent device representation ([`Device`], [`SshStatus`], …).
//! - [`store`] — a SQLite working store with JSON import/export ([`Store`]).
//! - [`paths`] — per-platform data directory resolution.

pub mod error;
pub mod model;
pub mod paths;
pub mod store;

pub use error::{CoreError, Result};
pub use model::{
    Device, DeviceNames, DeviceStatus, MacAddr, SshInfo, SshStatus, build_ssh_command,
    clean_hostname, suggest_usernames, unix_now,
};
pub use store::Store;
