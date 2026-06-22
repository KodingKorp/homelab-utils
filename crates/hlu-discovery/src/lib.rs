//! Async LAN discovery and SSH-probe engine for **homelab-utils**.
//!
//! Intentionally GUI-free: the desktop app links this directly and the `hlu-discover` CLI wraps
//! it, so both share one engine. The default pipeline is privilege-free — a bounded TCP sweep,
//! the OS ARP cache, mDNS, reverse-DNS and OUI vendor lookup — and produces [`hlu_core::Device`]
//! records ready to persist.

pub mod arp;
pub mod mdns;
pub mod oui;
pub mod rdns;
pub mod ssh;
pub mod subnet;
pub mod sweep;

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use hlu_core::{Device, DeviceStatus, SshStatus, suggest_usernames};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

pub use ssh::{SshProbeResult, probe as ssh_probe};

/// Errors the discovery engine can surface.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// No local IPv4 subnet could be determined and no explicit host list was given.
    #[error("could not determine the local subnet to scan")]
    NoSubnet,
    /// A core/persistence error bubbled up.
    #[error(transparent)]
    Core(#[from] hlu_core::CoreError),
}

/// Convenience alias for results from this crate.
pub type Result<T> = std::result::Result<T, DiscoveryError>;

/// Tunable parameters for a discovery pass.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Explicit hosts to scan. When `None`, the `/24` around the primary IPv4 is used.
    pub hosts: Option<Vec<Ipv4Addr>>,
    /// TCP ports probed during the sweep (liveness + role fingerprint).
    pub ports: Vec<u16>,
    /// Max concurrent connects during the sweep.
    pub concurrency: usize,
    /// Per-connect (and per banner-read) timeout.
    pub connect_timeout: Duration,
    /// How long to browse mDNS.
    pub mdns_duration: Duration,
    /// Whether to run the mDNS browse.
    pub enable_mdns: bool,
    /// Whether to run the SSH banner probe on hosts with port 22 open.
    pub enable_ssh_probe: bool,
    /// Max concurrent reverse-DNS/SSH enrichment tasks.
    pub enrich_concurrency: usize,
    /// Current OS username, used to seed SSH login suggestions.
    pub current_user: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            hosts: None,
            // Small, common homelab port set: SSH, web, SMB, Proxmox, Plex, RDP, VNC.
            ports: vec![22, 80, 443, 445, 8006, 32400, 3389, 5900],
            concurrency: 256,
            connect_timeout: Duration::from_millis(700),
            mdns_duration: Duration::from_secs(2),
            enable_mdns: true,
            enable_ssh_probe: true,
            enrich_concurrency: 64,
            current_user: None,
        }
    }
}

impl ScanConfig {
    /// Resolve the concrete host list to scan.
    fn resolve_hosts(&self) -> Result<Vec<Ipv4Addr>> {
        match &self.hosts {
            Some(hosts) => Ok(hosts.clone()),
            None => subnet::default_hosts()
                .map(|(_, hosts)| hosts)
                .ok_or(DiscoveryError::NoSubnet),
        }
    }
}

/// Run one full discovery pass and return the devices found, sorted by IP.
///
/// The sweep and mDNS browse run concurrently; per-host reverse-DNS and SSH probing are then
/// fanned out under a concurrency cap.
pub async fn discover(config: &ScanConfig) -> Result<Vec<Device>> {
    let hosts = config.resolve_hosts()?;
    let host_set: HashSet<IpAddr> = hosts.iter().copied().map(IpAddr::V4).collect();

    // Liveness sweep and mDNS browse have no data dependency — run them together.
    let sweep = sweep::tcp_sweep(
        &hosts,
        &config.ports,
        config.concurrency,
        config.connect_timeout,
    );
    let mdns = async {
        if config.enable_mdns {
            mdns::browse(config.mdns_duration).await
        } else {
            Default::default()
        }
    };
    let (open_ports, mdns_map) = tokio::join!(sweep, mdns);

    // The ARP cache is most useful *after* the sweep has populated it.
    let arp = arp::read_arp_cache().await;
    let vendor_db = oui::VendorDb::load();

    // Union of everything we have evidence for, scoped to the subnet we scanned.
    let mut candidates: HashSet<IpAddr> = HashSet::new();
    candidates.extend(open_ports.keys().copied());
    candidates.extend(mdns_map.keys().copied().filter(|ip| host_set.contains(ip)));
    candidates.extend(arp.keys().copied().filter(|ip| host_set.contains(ip)));

    // Build base records synchronously (cheap, in-memory lookups only).
    let mut base: Vec<Device> = Vec::with_capacity(candidates.len());
    for ip in candidates {
        let mut device = Device::seen(ip);
        device.status = DeviceStatus::Online;
        if let Some(ports) = open_ports.get(&ip) {
            device.open_ports = ports.clone();
        }
        if let Some(mac) = arp.get(&ip) {
            device.set_mac(mac.clone());
            if let Some(db) = &vendor_db {
                device.vendor = db.lookup(mac);
            }
        }
        if let Some(record) = mdns_map.get(&ip) {
            device.names.mdns_hostname = record.hostname.clone();
            device.names.mdns_services = record.services.clone();
        }
        base.push(device);
    }

    // Enrich each device with reverse-DNS and an SSH probe, concurrently but bounded.
    let semaphore = Arc::new(Semaphore::new(config.enrich_concurrency.max(1)));
    let config = config.clone();
    let mut tasks = JoinSet::new();
    for mut device in base {
        let semaphore = semaphore.clone();
        let config = config.clone();
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            device.names.reverse_dns = rdns::reverse_dns(device.ip).await;
            enrich_ssh(&mut device, &config).await;
            device
        });
    }

    let mut devices = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(device) = result {
            devices.push(device);
        }
    }
    devices.sort_by_key(|d| d.ip);
    Ok(devices)
}

/// Probe SSH on port 22 (when open) and populate the device's [`hlu_core::SshInfo`].
async fn enrich_ssh(device: &mut Device, config: &ScanConfig) {
    if config.enable_ssh_probe && device.open_ports.contains(&22) {
        let result = ssh::probe(device.ip, 22, config.connect_timeout).await;
        device.ssh.port = Some(22);
        device.ssh.status = result.status;
        device.ssh.banner = result.banner;
        device.ssh.suggested_users =
            suggest_usernames(result.os_hint.as_deref(), config.current_user.as_deref());
        device.ssh.os_hint = result.os_hint;
    } else {
        device.ssh.status = SshStatus::Unknown;
        device.ssh.suggested_users = suggest_usernames(None, config.current_user.as_deref());
    }
}
