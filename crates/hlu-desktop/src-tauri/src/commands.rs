//! Tauri commands — the bridge between the React frontend and the discovery engine + store.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use hlu_core::{
    AuthMethod, CredentialMeta, Device, DeviceStatus, ServicePort, Store, StoredCredential,
    unix_now,
};
use hlu_discovery::portscan::{self, COMMON_PORTS, PortScanConfig};
use hlu_discovery::{ScanConfig, discover};
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use zeroize::Zeroizing;

use crate::state::AppState;
use crate::terminals::TerminalInfo;
use crate::{clipboard, crypto, terminals};

/// `app_settings` key under which the user's preferred terminal id is stored.
const DEFAULT_TERMINAL_KEY: &str = "default_terminal";

/// Command results surface a plain `String` error to the frontend.
type CmdResult<T> = Result<T, String>;

fn lock_err<E>(_: E) -> String {
    "internal error: inventory lock poisoned".to_string()
}

fn current_user() -> Option<String> {
    std::env::var("USERNAME")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .filter(|u| !u.is_empty())
}

/// Run a discovery pass, merge it with the persisted inventory, and return the **full** inventory.
///
/// Devices not seen this round are kept and marked offline (rather than dropped from the returned
/// list), so a saved-but-currently-unreachable device never silently vanishes from the UI.
#[tauri::command]
pub async fn scan(
    state: State<'_, AppState>,
    enable_mdns: Option<bool>,
    enable_ssh: Option<bool>,
) -> CmdResult<Vec<Device>> {
    let config = ScanConfig {
        enable_mdns: enable_mdns.unwrap_or(true),
        enable_ssh_probe: enable_ssh.unwrap_or(true),
        current_user: current_user(),
        ..Default::default()
    };

    // The scan itself is fully async; no lock is held across this await.
    let mut devices = discover(&config).await.map_err(|e| e.to_string())?;

    let mut store = state.store.lock().map_err(lock_err)?;

    // Index the existing inventory so we can carry over user-owned + previously-scanned data and
    // detect which devices were NOT seen this round.
    let mut previous: HashMap<String, Device> = store
        .all()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|d| (d.id.clone(), d))
        .collect();

    for device in &mut devices {
        if let Some(existing) = previous.remove(&device.id) {
            // Preserve user-owned fields and the original first-seen timestamp.
            device.custom_name = existing.custom_name;
            device.ssh_user = existing.ssh_user;
            device.first_seen = existing.first_seen.min(device.first_seen);
            // The quick discovery sweep doesn't deep-scan ports — keep prior service results.
            if device.services.is_empty() {
                device.services = existing.services;
                device.ports_scanned_at = existing.ports_scanned_at;
            }
        }
    }

    // Whatever's left in `previous` was a no-show this round → keep it, marked offline.
    let mut merged = devices;
    for (_id, mut gone) in previous {
        gone.status = DeviceStatus::Offline;
        merged.push(gone);
    }

    store.upsert_many(&merged).map_err(|e| e.to_string())?;
    // Return the full inventory (most-recently-seen first) so the list stays stable.
    store.all().map_err(|e| e.to_string())
}

/// Return the persisted inventory (e.g. on app start, before the first scan).
#[tauri::command]
pub fn list_devices(state: State<'_, AppState>) -> CmdResult<Vec<Device>> {
    let store = state.store.lock().map_err(lock_err)?;
    store.all().map_err(|e| e.to_string())
}

/// Set or clear a device's user-supplied display name.
#[tauri::command]
pub fn set_custom_name(
    state: State<'_, AppState>,
    id: String,
    name: Option<String>,
) -> CmdResult<()> {
    let store = state.store.lock().map_err(lock_err)?;
    store
        .set_custom_name(&id, name.as_deref())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Forget a device: remove it from the inventory and delete any saved credential. Useful for a
/// saved-but-unreachable device the user no longer wants. (An online device will reappear on the
/// next scan.)
#[tauri::command]
pub fn remove_device(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let store = state.store.lock().map_err(lock_err)?;
    store.delete_device(&id).map_err(|e| e.to_string())?;
    // Credentials are keyed by MAC == id; drop any so we don't leave an orphan.
    store.delete_credential(&id).map_err(|e| e.to_string())?;
    Ok(())
}

/// Set or clear a device's chosen SSH login.
#[tauri::command]
pub fn set_username(state: State<'_, AppState>, id: String, user: Option<String>) -> CmdResult<()> {
    let store = state.store.lock().map_err(lock_err)?;
    store
        .set_username(&id, user.as_deref())
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Deep-scan a host's TCP ports and identify running services. With `full` (default), scans the
/// entire 1–65535 range; otherwise just the common homelab ports. Persists results onto the
/// matching device and returns them.
#[tauri::command]
pub async fn scan_ports(
    state: State<'_, AppState>,
    ip: String,
    full: Option<bool>,
) -> CmdResult<Vec<ServicePort>> {
    let addr: IpAddr = ip.parse().map_err(|_| format!("invalid ip: {ip}"))?;

    // Default to the fast common-ports scan; full 1–65535 only when explicitly requested.
    let full = full.unwrap_or(false);
    let ports: Vec<u16> = if full {
        (1..=65535).collect()
    } else {
        COMMON_PORTS.to_vec()
    };

    // A full sweep is dominated by the per-connect wait on filtered ports (throughput ≈
    // concurrency / connect_timeout). On a LAN a live host answers in ~1 ms, so for the full range
    // we use a tighter timeout and a wider worker pool than the WAN-safe defaults. (Windows still
    // rate-limits outbound connects, so this helps but a 65535 sweep is never instant — a raw/SYN
    // "deep scan" mode would be the real fix.)
    let config = if full {
        PortScanConfig {
            concurrency: 800,
            connect_timeout: Duration::from_millis(150),
            ..Default::default()
        }
    } else {
        PortScanConfig::default()
    };
    let services = portscan::scan_host(addr, ports, &config).await;

    // Persist the results onto the matching device (looked up by IP).
    {
        let store = state.store.lock().map_err(lock_err)?;
        if let Ok(devices) = store.all() {
            if let Some(mut device) = devices.into_iter().find(|d| d.ip.to_string() == ip) {
                device.services = services.clone();
                device.ports_scanned_at = Some(unix_now());
                let _ = store.upsert(&device);
            }
        }
    }

    Ok(services)
}

/// Build the `ssh` command for a device and copy it to the clipboard; returns the command.
#[tauri::command]
pub fn copy_ssh_command(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
    user: Option<String>,
) -> CmdResult<String> {
    let device = {
        let store = state.store.lock().map_err(lock_err)?;
        store
            .get(&id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("device {id} not found"))?
    };

    let user = user
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| device.chosen_user());
    let command = device.ssh_command(&user);

    app.clipboard()
        .write_text(command.clone())
        .map_err(|e| e.to_string())?;
    Ok(command)
}

// ===================================================================================================
// SSH credentials (per-device, encrypted) + terminal launching.
//
// Credentials are keyed by MAC (== Device.id when a MAC is known); only devices that have a MAC
// can have credentials. The plaintext password is never returned to the frontend — it is decrypted
// server-side straight onto the clipboard, or used to launch a terminal.
// ===================================================================================================

/// Load a device that must exist and have a MAC, rejecting otherwise.
fn load_mac_device(store: &Store, mac: &str) -> CmdResult<Device> {
    let device = store
        .get(mac)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("device {mac} not found"))?;
    if device.mac.is_none() {
        return Err("this device has no MAC address; credentials are unavailable".to_string());
    }
    Ok(device)
}

/// Upsert a credential, preserving the original `created_at` when one already exists.
fn upsert_cred(store: &Store, mut cred: StoredCredential) -> CmdResult<()> {
    if let Some(existing) = store.get_credential(&cred.mac).map_err(|e| e.to_string())? {
        cred.created_at = existing.created_at;
    }
    store.upsert_credential(&cred).map_err(|e| e.to_string())
}

/// Build the `ssh` argv: `ssh [-i key] [-p port] user@host`.
fn build_ssh_argv(host: &str, user: &str, port: u16, key_path: Option<&str>) -> Vec<String> {
    let mut argv = vec!["ssh".to_string()];
    if let Some(key) = key_path {
        argv.push("-i".to_string());
        argv.push(key.to_string());
    }
    if port != 22 {
        argv.push("-p".to_string());
        argv.push(port.to_string());
    }
    argv.push(format!("{user}@{host}"));
    argv
}

/// Resolve which terminal to launch: the explicit request, else the saved default, else the first
/// detected emulator on this machine.
fn resolve_terminal(store: &Store, requested: Option<String>) -> CmdResult<String> {
    if let Some(id) = requested.filter(|s| !s.trim().is_empty()) {
        return Ok(id);
    }
    if let Some(id) = store
        .get_setting(DEFAULT_TERMINAL_KEY)
        .map_err(|e| e.to_string())?
        .filter(|s| !s.trim().is_empty())
    {
        return Ok(id);
    }
    terminals::available()
        .into_iter()
        .next()
        .map(|t| t.id)
        .ok_or_else(|| "no terminal emulator found on this system".to_string())
}

/// Save an encrypted password for a device (keyed by MAC). Switches the credential to password auth.
#[tauri::command]
pub fn set_ssh_password(
    state: State<'_, AppState>,
    mac: String,
    password: String,
) -> CmdResult<()> {
    let password = Zeroizing::new(password);
    if password.is_empty() {
        return Err("password must not be empty".to_string());
    }
    // Encrypt before taking the lock — the keychain round-trip must not hold the inventory mutex.
    let (cipher, nonce) =
        crypto::encrypt_password(&mac, password.as_str()).map_err(|e| e.to_string())?;

    let store = state.store.lock().map_err(lock_err)?;
    load_mac_device(&store, &mac)?;
    let now = unix_now();
    upsert_cred(
        &store,
        StoredCredential {
            mac,
            auth_method: AuthMethod::Password,
            pw_cipher: Some(cipher),
            pw_nonce: Some(nonce),
            key_path: None,
            created_at: now,
            updated_at: now,
        },
    )
}

/// Save a path to an SSH private key for a device. Switches the credential to key auth.
#[tauri::command]
pub fn set_ssh_key(state: State<'_, AppState>, mac: String, key_path: String) -> CmdResult<()> {
    let trimmed = key_path.trim();
    if trimmed.is_empty() {
        return Err("key path must not be empty".to_string());
    }
    if !std::path::Path::new(trimmed).is_file() {
        return Err(format!("no such key file: {trimmed}"));
    }
    let store = state.store.lock().map_err(lock_err)?;
    load_mac_device(&store, &mac)?;
    let now = unix_now();
    upsert_cred(
        &store,
        StoredCredential {
            mac,
            auth_method: AuthMethod::Key,
            pw_cipher: None,
            pw_nonce: None,
            key_path: Some(trimmed.to_string()),
            created_at: now,
            updated_at: now,
        },
    )
}

/// Remove any stored credential for a device.
#[tauri::command]
pub fn clear_credential(state: State<'_, AppState>, mac: String) -> CmdResult<()> {
    let store = state.store.lock().map_err(lock_err)?;
    store.delete_credential(&mac).map_err(|e| e.to_string())?;
    Ok(())
}

/// Return non-secret metadata about a device's stored credential (never the password itself).
#[tauri::command]
pub fn get_credential_meta(
    state: State<'_, AppState>,
    mac: String,
) -> CmdResult<Option<CredentialMeta>> {
    let store = state.store.lock().map_err(lock_err)?;
    store.get_credential_meta(&mac).map_err(|e| e.to_string())
}

/// Decrypt the stored password and copy it to the clipboard as sensitive data. Returns nothing —
/// the plaintext never crosses back to the frontend.
#[tauri::command]
pub fn copy_ssh_password(app: AppHandle, state: State<'_, AppState>, mac: String) -> CmdResult<()> {
    let cred = {
        let store = state.store.lock().map_err(lock_err)?;
        store
            .get_credential(&mac)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "no saved password for this device".to_string())?
    };
    if cred.auth_method != AuthMethod::Password {
        return Err("this device has no saved password".to_string());
    }
    let cipher = cred
        .pw_cipher
        .as_deref()
        .ok_or_else(|| "saved password is incomplete".to_string())?;
    let nonce = cred
        .pw_nonce
        .as_deref()
        .ok_or_else(|| "saved password is incomplete".to_string())?;
    let password = crypto::decrypt_password(&mac, cipher, nonce).map_err(|e| e.to_string())?;
    clipboard::copy_secret(&app, password.as_str())
}

/// List terminal emulators detected on this machine.
#[tauri::command]
pub fn list_terminals() -> CmdResult<Vec<TerminalInfo>> {
    Ok(terminals::available())
}

/// Read the user's preferred default terminal id, if set.
#[tauri::command]
pub fn get_default_terminal(state: State<'_, AppState>) -> CmdResult<Option<String>> {
    let store = state.store.lock().map_err(lock_err)?;
    store
        .get_setting(DEFAULT_TERMINAL_KEY)
        .map_err(|e| e.to_string())
}

/// Persist the user's preferred default terminal id.
#[tauri::command]
pub fn set_default_terminal(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    let store = state.store.lock().map_err(lock_err)?;
    store
        .set_setting(DEFAULT_TERMINAL_KEY, &id)
        .map_err(|e| e.to_string())
}

/// Open a terminal running `ssh` to a device. For key auth, launches `ssh -i <key> …` directly;
/// for password auth, copies the password to the clipboard first so the user can paste at the
/// prompt; with no stored credential, just opens `ssh user@host`.
#[tauri::command]
pub fn open_ssh_terminal(
    app: AppHandle,
    state: State<'_, AppState>,
    mac: String,
    terminal_id: Option<String>,
) -> CmdResult<()> {
    // Gather everything under the lock, then release it before decrypting / copying / launching.
    let (user, host, port, terminal, cred) = {
        let store = state.store.lock().map_err(lock_err)?;
        let device = load_mac_device(&store, &mac)?;
        let terminal = resolve_terminal(&store, terminal_id)?;
        let cred = store.get_credential(&mac).map_err(|e| e.to_string())?;
        (
            device.chosen_user(),
            device.ip.to_string(),
            device.ssh.port.unwrap_or(22),
            terminal,
            cred,
        )
    };

    let argv = match &cred {
        Some(c) if c.auth_method == AuthMethod::Key => {
            let key = c
                .key_path
                .as_deref()
                .ok_or_else(|| "saved key has no path".to_string())?;
            if !std::path::Path::new(key).is_file() {
                return Err(format!("saved key file is missing: {key}"));
            }
            build_ssh_argv(&host, &user, port, Some(key))
        }
        Some(c) if c.auth_method == AuthMethod::Password => {
            let cipher = c
                .pw_cipher
                .as_deref()
                .ok_or_else(|| "saved password is incomplete".to_string())?;
            let nonce = c
                .pw_nonce
                .as_deref()
                .ok_or_else(|| "saved password is incomplete".to_string())?;
            let password =
                crypto::decrypt_password(&mac, cipher, nonce).map_err(|e| e.to_string())?;
            clipboard::copy_secret(&app, password.as_str())?;
            build_ssh_argv(&host, &user, port, None)
        }
        _ => build_ssh_argv(&host, &user, port, None),
    };

    terminals::launch(&terminal, &argv)
}
