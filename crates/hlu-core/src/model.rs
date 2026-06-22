//! Core domain model: the persistent, GUI-agnostic representation of a homelab.
//!
//! These types are shared by the discovery engine, the CLI, and the desktop app, and are
//! serialized both into the SQLite working store and the human-readable JSON export.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// A MAC address in canonical lowercase form, e.g. `aa:bb:cc:dd:ee:ff`.
pub type MacAddr = String;

/// Result of probing a host for SSH.
///
/// These states are deliberately distinct: a successful TCP connect only proves the port is
/// open, while [`SshStatus::ConfirmedSsh`] means we actually read an `SSH-` identification
/// banner. Surfacing them separately avoids a misleading "green" status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshStatus {
    /// Not yet probed.
    #[default]
    Unknown,
    /// The probe could not reach the port (closed/filtered/timed out).
    Unreachable,
    /// The TCP port accepted a connection but no SSH banner was confirmed.
    PortReachable,
    /// An `SSH-` identification banner was read — this host speaks SSH.
    ConfirmedSsh,
}

/// SSH-related facts discovered about a host.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SshInfo {
    /// Current probe result.
    pub status: SshStatus,
    /// The port the probe targeted (usually 22).
    pub port: Option<u16>,
    /// Raw identification banner, e.g. `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3`.
    pub banner: Option<String>,
    /// Best-effort OS hint parsed from the banner comment.
    pub os_hint: Option<String>,
    /// Heuristic, user-editable login suggestions (never authoritative — SSH does not
    /// reveal usernames before auth).
    pub suggested_users: Vec<String>,
}

/// Liveness of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    /// Responded during the most recent scan.
    Online,
    /// Known previously but did not respond in the most recent scan.
    Offline,
    /// Never confirmed online.
    #[default]
    Unknown,
}

/// Naming signals gathered from different discovery sources, kept separately so the display
/// name can be re-derived if the user clears their override.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceNames {
    /// Hostname advertised over mDNS (`.local`).
    pub mdns_hostname: Option<String>,
    /// mDNS service types seen, e.g. `_ssh._tcp`, `_http._tcp`.
    pub mdns_services: Vec<String>,
    /// UPnP/SSDP friendly name.
    pub upnp_friendly_name: Option<String>,
    /// Reverse-DNS (PTR) name.
    pub reverse_dns: Option<String>,
    /// NetBIOS/LLMNR name.
    pub netbios: Option<String>,
}

/// An open TCP port found during a deep scan, with a best-effort service/app identification.
///
/// Two layers of identity: `service` is the *protocol/role* (HTTP, HTTPS, SSH, Redis…), always a
/// best guess from the well-known-port table and refined by any banner; `product` is the *concrete
/// application* (Grafana, Proxmox VE, OpenSSH, nginx…), set only on a confident banner or
/// HTTP-fingerprint match. UIs should prefer `product` and fall back to `service`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServicePort {
    /// The open port number.
    pub port: u16,
    /// Protocol/role (HTTP, HTTPS, SSH, Redis…) from the well-known-port table and/or banner.
    pub service: Option<String>,
    /// Concrete application/product, when confidently identified (e.g. "Grafana", "OpenSSH").
    #[serde(default)]
    pub product: Option<String>,
    /// Product version, when derivable from a banner or `Server:` header (e.g. "9.6p1", "1.25.3").
    #[serde(default)]
    pub version: Option<String>,
    /// Web page `<title>` for HTTP(S) services, normalized and length-capped.
    #[serde(default)]
    pub title: Option<String>,
    /// First line of any banner / HTTP status read from the port.
    pub banner: Option<String>,
}

/// A single discovered device on the local network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// Stable identity key — the MAC when known, otherwise the IP.
    pub id: String,
    /// Most recently observed IP address.
    pub ip: IpAddr,
    /// Hardware (MAC) address, when resolvable from the ARP cache.
    pub mac: Option<MacAddr>,
    /// Vendor inferred from the MAC OUI.
    pub vendor: Option<String>,
    /// User-supplied name; when set it overrides the auto-derived name.
    pub custom_name: Option<String>,
    /// User-chosen SSH login; when set it overrides the heuristic suggestions.
    #[serde(default)]
    pub ssh_user: Option<String>,
    /// Naming signals from discovery sources.
    pub names: DeviceNames,
    /// Liveness from the latest scan.
    pub status: DeviceStatus,
    /// SSH probe details.
    pub ssh: SshInfo,
    /// Open TCP ports observed during the quick discovery sweep.
    pub open_ports: Vec<u16>,
    /// Deep port-scan results: open ports with identified services (populated by the Ports tool).
    #[serde(default)]
    pub services: Vec<ServicePort>,
    /// Unix seconds of the last deep port scan, if any.
    #[serde(default)]
    pub ports_scanned_at: Option<i64>,
    /// Unix seconds when first discovered.
    pub first_seen: i64,
    /// Unix seconds of the most recent sighting.
    pub last_seen: i64,
}

impl Device {
    /// Create a freshly-seen device from an IP, stamping first/last seen to now.
    pub fn seen(ip: IpAddr) -> Self {
        let now = unix_now();
        Self {
            id: ip.to_string(),
            ip,
            mac: None,
            vendor: None,
            custom_name: None,
            ssh_user: None,
            names: DeviceNames::default(),
            status: DeviceStatus::Online,
            ssh: SshInfo::default(),
            open_ports: Vec::new(),
            services: Vec::new(),
            ports_scanned_at: None,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Adopt the MAC as the stable identity key (preferred over IP, which can change).
    pub fn set_mac(&mut self, mac: MacAddr) {
        self.id = mac.clone();
        self.mac = Some(mac);
    }

    /// The name to show in UIs: the user override if present, else an auto-derived name.
    pub fn display_name(&self) -> String {
        if let Some(name) = &self.custom_name {
            if !name.trim().is_empty() {
                return name.clone();
            }
        }
        self.derive_display_name()
    }

    /// Best auto-derived name from the available discovery signals.
    pub fn derive_display_name(&self) -> String {
        if let Some(n) = &self.names.mdns_hostname {
            return clean_hostname(n);
        }
        if let Some(n) = &self.names.upnp_friendly_name {
            return n.clone();
        }
        if let Some(n) = &self.names.reverse_dns {
            return clean_hostname(n);
        }
        if let Some(n) = &self.names.netbios {
            return n.clone();
        }
        if let Some(v) = &self.vendor {
            return format!("{v} @ {}", self.ip);
        }
        self.ip.to_string()
    }

    /// Build the `ssh` command for this device for the given user.
    pub fn ssh_command(&self, user: &str) -> String {
        let port = self.ssh.port.unwrap_or(22);
        build_ssh_command(&self.ip.to_string(), user, port)
    }

    /// The best login to use: the user's explicit choice, else the top heuristic suggestion,
    /// else `root`.
    pub fn chosen_user(&self) -> String {
        self.ssh_user
            .clone()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| self.ssh.suggested_users.first().cloned())
            .unwrap_or_else(|| "root".to_string())
    }
}

/// Format an `ssh` command, only emitting `-p` when the port is non-standard.
pub fn build_ssh_command(host: &str, user: &str, port: u16) -> String {
    if port == 22 {
        format!("ssh {user}@{host}")
    } else {
        format!("ssh -p {port} {user}@{host}")
    }
}

/// Build an ordered, de-duplicated list of heuristic login suggestions.
///
/// The current OS user (if provided) is preferred first, then OS-specific defaults inferred
/// from the SSH banner, then common appliance/cloud-image defaults. None of these are
/// authoritative — the UI must let the user edit the chosen username.
pub fn suggest_usernames(os_hint: Option<&str>, current_user: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let push = |out: &mut Vec<String>, candidate: &str| {
        let c = candidate.trim();
        if !c.is_empty() && !out.iter().any(|x| x == c) {
            out.push(c.to_string());
        }
    };

    if let Some(user) = current_user {
        push(&mut out, user);
    }

    let hint = os_hint.unwrap_or_default().to_lowercase();
    if hint.contains("raspbian") || hint.contains("raspberry") {
        push(&mut out, "pi");
    }
    if hint.contains("ubuntu") {
        push(&mut out, "ubuntu");
    }
    if hint.contains("debian") {
        push(&mut out, "debian");
    }

    for default in [
        "root", "admin", "pi", "ubuntu", "debian", "core", "ec2-user",
    ] {
        push(&mut out, default);
    }
    out
}

/// Strip the trailing `.local.`/`.` that mDNS and PTR names carry.
pub fn clean_hostname(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    trimmed
        .strip_suffix(".local")
        .unwrap_or(trimmed)
        .to_string()
}

/// Current time in whole Unix seconds (saturates to 0 before the epoch).
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_command_omits_default_port() {
        assert_eq!(build_ssh_command("10.0.0.5", "pi", 22), "ssh pi@10.0.0.5");
        assert_eq!(
            build_ssh_command("10.0.0.5", "pi", 2222),
            "ssh -p 2222 pi@10.0.0.5"
        );
    }

    #[test]
    fn suggestions_prefer_current_user_and_dedup() {
        let s = suggest_usernames(Some("SSH-2.0-OpenSSH_9.6 Ubuntu"), Some("shivam"));
        assert_eq!(s.first().unwrap(), "shivam");
        assert!(s.contains(&"ubuntu".to_string()));
        // no duplicates
        let mut sorted = s.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), s.len());
    }

    #[test]
    fn clean_hostname_strips_local_suffix() {
        assert_eq!(clean_hostname("rpi.local."), "rpi");
        assert_eq!(clean_hostname("host."), "host");
    }

    #[test]
    fn service_port_deserializes_legacy_json_without_new_fields() {
        // A row persisted before product/version/title existed must still load (fields default
        // to None), since devices are stored as full JSON blobs in SQLite.
        let legacy = r#"{"port":80,"service":"HTTP","banner":"HTTP/1.1 200 OK"}"#;
        let sp: ServicePort = serde_json::from_str(legacy).unwrap();
        assert_eq!(sp.port, 80);
        assert_eq!(sp.service.as_deref(), Some("HTTP"));
        assert_eq!(sp.product, None);
        assert_eq!(sp.version, None);
        assert_eq!(sp.title, None);

        // Full round-trip keeps every field.
        let full = ServicePort {
            port: 3000,
            service: Some("HTTP".into()),
            product: Some("Grafana".into()),
            version: Some("10.4.0".into()),
            title: Some("Grafana".into()),
            banner: Some("HTTP/1.1 302 Found".into()),
        };
        let json = serde_json::to_string(&full).unwrap();
        let back: ServicePort = serde_json::from_str(&json).unwrap();
        assert_eq!(back.product.as_deref(), Some("Grafana"));
        assert_eq!(back.version.as_deref(), Some("10.4.0"));
        assert_eq!(back.title.as_deref(), Some("Grafana"));
    }

    #[test]
    fn display_name_prefers_custom_then_mdns() {
        let mut d = Device::seen("192.168.1.10".parse().unwrap());
        d.names.mdns_hostname = Some("nas.local.".into());
        assert_eq!(d.display_name(), "nas");
        d.custom_name = Some("Big NAS".into());
        assert_eq!(d.display_name(), "Big NAS");
    }
}
