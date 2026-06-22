//! mDNS / DNS-SD discovery via `mdns-sd`.
//!
//! We browse a fixed set of common service types for a bounded window and collect resolved
//! instances, mapping each advertised IP to its hostname and the services it offers. This needs
//! no privileges; it only sees devices that actively advertise over multicast.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};

/// Naming signals gathered for one IP over mDNS.
#[derive(Debug, Default, Clone)]
pub struct MdnsRecord {
    /// Advertised `.local` hostname.
    pub hostname: Option<String>,
    /// Service types seen for this host, e.g. `_ssh._tcp`.
    pub services: Vec<String>,
}

/// Service types we actively browse. Kept small and common to stay polite on the network.
const SERVICE_TYPES: &[&str] = &[
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_workstation._tcp.local.",
    "_device-info._tcp.local.",
    "_smb._tcp.local.",
    "_rfb._tcp.local.",
    "_ipp._tcp.local.",
];

/// Browse for `duration`, returning `ip → MdnsRecord`. Errors are swallowed into an empty map.
pub async fn browse(duration: Duration) -> HashMap<IpAddr, MdnsRecord> {
    tokio::task::spawn_blocking(move || browse_blocking(duration))
        .await
        .unwrap_or_default()
}

fn browse_blocking(duration: Duration) -> HashMap<IpAddr, MdnsRecord> {
    let mut map: HashMap<IpAddr, MdnsRecord> = HashMap::new();

    let Ok(daemon) = ServiceDaemon::new() else {
        return map;
    };

    let receivers: Vec<_> = SERVICE_TYPES
        .iter()
        .filter_map(|service_type| {
            daemon
                .browse(service_type)
                .ok()
                .map(|rx| (*service_type, rx))
        })
        .collect();

    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let mut progressed = false;
        for (service_type, rx) in &receivers {
            while let Ok(event) = rx.try_recv() {
                progressed = true;
                if let ServiceEvent::ServiceResolved(info) = event {
                    let service = service_type.trim_end_matches(".local.").to_string();
                    let hostname = clean_local(info.get_hostname());
                    for addr in info.get_addresses() {
                        let record = map.entry(addr.to_ip_addr()).or_default();
                        record.hostname.get_or_insert_with(|| hostname.clone());
                        if !record.services.contains(&service) {
                            record.services.push(service.clone());
                        }
                    }
                }
            }
        }
        if !progressed {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let _ = daemon.shutdown();
    map
}

fn clean_local(hostname: &str) -> String {
    hostname.trim_end_matches('.').to_string()
}
