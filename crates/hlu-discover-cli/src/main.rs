//! `hlu-discover` — a standalone CLI over the homelab-utils discovery engine.
//!
//! Runs a privilege-free LAN scan and prints discovered devices, optionally as JSON or with a
//! one-shot "copy the ssh command for host X" action. It links the same `hlu-discovery` engine
//! the desktop app uses, and deliberately pulls in no GUI dependencies.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use hlu_core::{Device, SshStatus};
use hlu_discovery::{ScanConfig, discover};
use tracing_subscriber::EnvFilter;

/// Discover homelab devices on your local network.
#[derive(Debug, Parser)]
#[command(name = "hlu-discover", version, about, long_about = None)]
struct Cli {
    /// Print the result as JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// Skip mDNS/DNS-SD browsing.
    #[arg(long)]
    no_mdns: bool,

    /// Skip the SSH banner probe.
    #[arg(long)]
    no_ssh: bool,

    /// Per-connect timeout in milliseconds.
    #[arg(long, default_value_t = 700)]
    timeout_ms: u64,

    /// Maximum concurrent connects during the sweep.
    #[arg(long, default_value_t = 256)]
    concurrency: usize,

    /// Username for the ssh command and login suggestions (defaults to the current OS user).
    #[arg(long)]
    user: Option<String>,

    /// Instead of listing, copy the `ssh` command for this IP to the clipboard.
    #[arg(long, value_name = "IP")]
    copy: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let user = cli.user.clone().or_else(current_user);

    let config = ScanConfig {
        enable_mdns: !cli.no_mdns,
        enable_ssh_probe: !cli.no_ssh,
        connect_timeout: Duration::from_millis(cli.timeout_ms),
        concurrency: cli.concurrency,
        current_user: user.clone(),
        ..Default::default()
    };

    eprintln!("Scanning the local network…");
    let devices = discover(&config).await.context("discovery failed")?;

    if let Some(ip) = &cli.copy {
        return copy_ssh_command(&devices, ip, user.as_deref());
    }

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
    } else {
        print_table(&devices);
    }
    Ok(())
}

/// Copy the `ssh user@host` command for the device at `ip` to the clipboard.
fn copy_ssh_command(devices: &[Device], ip: &str, user: Option<&str>) -> Result<()> {
    let device = devices
        .iter()
        .find(|d| d.ip.to_string() == ip)
        .with_context(|| format!("no device at {ip} in this scan"))?;

    let user = user
        .map(str::to_string)
        .or_else(|| device.ssh.suggested_users.first().cloned())
        .unwrap_or_else(|| "root".to_string());

    let command = device.ssh_command(&user);
    let mut clipboard = arboard::Clipboard::new().context("could not access the clipboard")?;
    clipboard
        .set_text(command.clone())
        .context("could not write to the clipboard")?;
    println!("Copied to clipboard: {command}");
    // On Linux/X11 a short-lived process can lose clipboard ownership on exit; echo so the user
    // always has the command regardless of platform clipboard quirks.
    Ok(())
}

fn print_table(devices: &[Device]) {
    if devices.is_empty() {
        println!("No devices found.");
        return;
    }

    println!(
        "{:<16} {:<24} {:<18} {:<6} VENDOR",
        "IP", "NAME", "MAC", "SSH"
    );
    println!("{}", "-".repeat(86));
    for device in devices {
        println!(
            "{:<16} {:<24} {:<18} {:<6} {}",
            device.ip.to_string(),
            truncate(&device.display_name(), 24),
            device.mac.clone().unwrap_or_else(|| "-".into()),
            ssh_label(device.ssh.status),
            device.vendor.clone().unwrap_or_default(),
        );
    }
    println!("\n{} device(s) found.", devices.len());
}

fn ssh_label(status: SshStatus) -> &'static str {
    match status {
        SshStatus::ConfirmedSsh => "yes",
        SshStatus::PortReachable => "open",
        SshStatus::Unreachable => "no",
        SshStatus::Unknown => "?",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn current_user() -> Option<String> {
    std::env::var("USERNAME")
        .ok()
        .or_else(|| std::env::var("USER").ok())
        .filter(|u| !u.is_empty())
}
