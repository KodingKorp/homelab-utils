//! Tauri commands — the bridge between the React frontend and the discovery engine + store.

use hlu_core::Device;
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
