//! Tauri commands — the bridge between the React frontend and the discovery engine + store.

use std::net::IpAddr;
use std::time::Duration;

use hlu_core::{Device, ServicePort, unix_now};
use hlu_discovery::portscan::{self, COMMON_PORTS, PortScanConfig};
use hlu_discovery::{ScanConfig, discover};
use tauri::{AppHandle, State};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::state::AppState;

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

/// Run a discovery pass, merge persisted user overrides, persist, and return the devices.
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
    for device in &mut devices {
        if let Ok(Some(existing)) = store.get(&device.id) {
            // Preserve user-owned fields and the original first-seen timestamp.
            device.custom_name = existing.custom_name;
            device.ssh_user = existing.ssh_user;
            device.first_seen = existing.first_seen.min(device.first_seen);
        }
    }
    store.upsert_many(&devices).map_err(|e| e.to_string())?;
    Ok(devices)
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
