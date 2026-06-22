//! homelab-utils desktop app (Tauri 2 backend).
//!
//! The Rust core registers plugins (clipboard, shell, updater), manages the device inventory,
//! and exposes [`commands`] to the React frontend. Heavy work (network scanning) runs in the
//! `hlu-discovery` engine; this layer is just glue + persistence.

mod commands;
mod state;

/// Build and run the desktop application.
pub fn run() {
    // Honour RUST_LOG if set; ignore failure if a subscriber is already installed.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_shell::init())
        // Auto-update from GitHub Releases (minisign-verified against the pubkey in tauri.conf.json).
        // tauri-plugin-process provides relaunch() after an update is installed.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .manage(state::AppState::new())
        .invoke_handler(tauri::generate_handler![
            commands::scan,
            commands::scan_ports,
            commands::list_devices,
            commands::set_custom_name,
            commands::set_username,
            commands::copy_ssh_command,
        ])
        .run(tauri::generate_context!())
        .expect("error while running the homelab-utils desktop app");
}
