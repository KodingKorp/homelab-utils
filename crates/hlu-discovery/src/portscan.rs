//! Deep TCP port scanning with best-effort service/application identification.
//!
//! Two phases: (1) a bounded connect-scan over the requested port range finds *open* ports
//! cheaply; (2) only those few open ports are then probed for a service banner (passive read,
//! falling back to a minimal HTTP request — many homelab apps are web UIs that send nothing
//! until asked). This keeps a full 1–65535 sweep affordable while still naming what's running.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hlu_core::ServicePort;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// A curated set of common homelab/service ports for a fast (non-full) scan.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 631, 993, 995,
    1080, 1433, 1521, 1883, 1900, 2049, 2375, 2376, 3000, 3128, 3306, 3389, 4000, 5000, 5001, 5060,
    5201, 5432, 5601, 5900, 5901, 6379, 7878, 8000, 8006, 8080, 8081, 8086, 8096, 8123, 8443, 8888,
    8920, 9000, 9090, 9091, 9100, 9200, 9443, 11434, 19999, 25565, 27017, 32400, 51820,
];

/// Tunables for a port scan.
#[derive(Debug, Clone)]
pub struct PortScanConfig {
    /// Max concurrent connects.
    pub concurrency: usize,
    /// Per-connect timeout during the open-port sweep.
    pub connect_timeout: Duration,
    /// Timeout for the service-identification banner/HTTP read.
    pub banner_timeout: Duration,
}

impl Default for PortScanConfig {
    fn default() -> Self {
        Self {
            // A fixed pool of this many workers (not one task per port) keeps memory and the
            // tokio scheduler load flat regardless of how many ports are scanned.
            concurrency: 400,
            connect_timeout: Duration::from_millis(250),
            banner_timeout: Duration::from_millis(400),
        }
    }
}

/// Scan `ports` on `ip`, returning the open ports with identified services, ordered by port.
pub async fn scan_host(ip: IpAddr, ports: Vec<u16>, config: &PortScanConfig) -> Vec<ServicePort> {
    let mut open = find_open_ports(ip, ports, config).await;
    open.sort_unstable();

    let semaphore = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    for port in open {
        let semaphore = semaphore.clone();
        let banner_timeout = config.banner_timeout;
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await.ok();
            identify(ip, port, banner_timeout).await
        });
    }

    let mut results = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(service) = joined {
            results.push(service);
        }
    }
    results.sort_by_key(|s| s.port);
    results
}

/// Find open ports using a fixed pool of workers that pull from a shared cursor over `ports`.
///
/// This caps the number of in-flight tasks (and half-open sockets) at `concurrency` no matter
/// how large the range — unlike spawning one task per port, which for a full 1–65535 sweep would
/// allocate 65k futures at once and spike CPU/memory.
async fn find_open_ports(ip: IpAddr, ports: Vec<u16>, config: &PortScanConfig) -> Vec<u16> {
    let ports = Arc::new(ports);
    let cursor = Arc::new(AtomicUsize::new(0));
    let timeout = config.connect_timeout;
    let workers = config.concurrency.max(1).min(ports.len().max(1));

    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        let ports = ports.clone();
        let cursor = cursor.clone();
        tasks.spawn(async move {
            let mut found = Vec::new();
            loop {
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                let Some(&port) = ports.get(index) else { break };
                let addr = SocketAddr::new(ip, port);
                if let Ok(Ok(_stream)) =
                    tokio::time::timeout(timeout, TcpStream::connect(addr)).await
                {
                    found.push(port);
                }
            }
            found
        });
    }

    let mut open = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        if let Ok(mut found) = joined {
            open.append(&mut found);
        }
    }
    open
}

/// Connect to an open port and identify the service: start from the well-known-port name, refine
/// it with any banner the server volunteers, and fall back to a minimal HTTP probe.
async fn identify(ip: IpAddr, port: u16, timeout: Duration) -> ServicePort {
    let mut service = well_known(port).map(str::to_string);
    let mut banner = None;

    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(timeout, TcpStream::connect(SocketAddr::new(ip, port))).await
    {
        // Many protocols (SSH, FTP, SMTP, Redis, …) send a banner immediately on connect.
        let mut buf = [0u8; 256];
        let read = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await;
        if let Ok(Ok(n)) = read {
            if n > 0 {
                let line = first_line(&buf[..n]);
                if !line.is_empty() {
                    refine_service(&mut service, &line);
                    banner = Some(line);
                }
            }
        }

        // No spontaneous banner: try a tiny HTTP request (covers web UIs / REST services).
        if banner.is_none() {
            let request =
                format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: homelab-utils\r\n\r\n");
            if stream.write_all(request.as_bytes()).await.is_ok() {
                let mut http = [0u8; 512];
                if let Ok(Ok(n)) = tokio::time::timeout(timeout, stream.read(&mut http)).await {
                    if n > 0 {
                        if let Some(summary) = parse_http(&http[..n]) {
                            service.get_or_insert_with(|| "HTTP".to_string());
                            banner = Some(summary);
                        }
                    }
                }
            }
        }
    }

    ServicePort {
        port,
        service,
        banner,
    }
}

fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().next().unwrap_or("").trim();
    line.chars().take(120).collect()
}

/// Summarize an HTTP response as `"<status> · <server>"` (or just the status), or `None` if the
/// reply isn't HTTP.
fn parse_http(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let status = text.lines().next()?.trim();
    if !status.starts_with("HTTP/") {
        return None;
    }
    let server = text.lines().find_map(|line| {
        let line = line.trim();
        line.to_ascii_lowercase()
            .strip_prefix("server:")
            .map(|_| line["server:".len()..].trim().to_string())
    });
    Some(match server {
        Some(server) if !server.is_empty() => format!("{status} · {server}"),
        _ => status.to_string(),
    })
}

/// Tighten the service name from a banner's distinctive prefix.
fn refine_service(service: &mut Option<String>, banner: &str) {
    let upper = banner.to_ascii_uppercase();
    let detected = if upper.starts_with("SSH-") {
        Some("SSH")
    } else if upper.starts_with("HTTP/") {
        Some("HTTP")
    } else if upper.starts_with("RFB ") {
        Some("VNC")
    } else if upper.contains("FTP") && upper.starts_with("220") {
        Some("FTP")
    } else if upper.starts_with("220") && (upper.contains("SMTP") || upper.contains("ESMTP")) {
        Some("SMTP")
    } else if upper.starts_with("-ERR") || upper.contains("REDIS") {
        Some("Redis")
    } else if upper.starts_with("+OK") {
        Some("POP3")
    } else if upper.starts_with("* OK") {
        Some("IMAP")
    } else {
        None
    };
    if let Some(name) = detected {
        *service = Some(name.to_string());
    }
}

/// Well-known port → service/application name, for the common homelab stack.
fn well_known(port: u16) -> Option<&'static str> {
    let name = match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 587 | 465 => "SMTP",
        53 => "DNS",
        80 | 8080 | 8000 | 8081 => "HTTP",
        110 | 995 => "POP3",
        111 => "RPCbind",
        135 => "MSRPC",
        139 | 445 => "SMB",
        143 | 993 => "IMAP",
        161 => "SNMP",
        389 => "LDAP",
        443 | 8443 | 9443 => "HTTPS",
        631 => "IPP/CUPS",
        1433 => "MSSQL",
        1521 => "Oracle DB",
        1883 => "MQTT",
        1900 => "SSDP/UPnP",
        2049 => "NFS",
        2375 | 2376 => "Docker API",
        3000 => "Grafana/Node",
        3128 => "Squid Proxy",
        3306 => "MySQL/MariaDB",
        3389 => "RDP",
        5000 | 5001 => "HTTP (dev)",
        5060 => "SIP",
        5201 => "iperf",
        5432 => "PostgreSQL",
        5601 => "Kibana",
        5900 | 5901 => "VNC",
        6379 => "Redis",
        7878 => "Radarr",
        8006 => "Proxmox VE",
        8086 => "InfluxDB",
        8096 | 8920 => "Jellyfin",
        8123 => "Home Assistant",
        8888 => "HTTP (alt)",
        9000 => "Portainer",
        9090 => "Prometheus/Cockpit",
        9091 => "Transmission",
        9100 => "Node Exporter",
        9200 => "Elasticsearch",
        11434 => "Ollama",
        19999 => "Netdata",
        25565 => "Minecraft",
        27017 => "MongoDB",
        32400 => "Plex",
        51820 => "WireGuard",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_names_common_ports() {
        assert_eq!(well_known(8006), Some("Proxmox VE"));
        assert_eq!(well_known(32400), Some("Plex"));
        assert_eq!(well_known(65000), None);
    }

    #[test]
    fn parses_http_server_header() {
        let resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_http(resp).as_deref(),
            Some("HTTP/1.1 200 OK · nginx/1.25")
        );
        assert!(parse_http(b"SSH-2.0-OpenSSH_9.6\r\n").is_none());
    }

    #[test]
    fn refines_service_from_banner() {
        let mut s = None;
        refine_service(&mut s, "SSH-2.0-OpenSSH_9.6p1");
        assert_eq!(s.as_deref(), Some("SSH"));
        let mut s2 = Some("HTTP".to_string());
        refine_service(&mut s2, "220 myftp FTP server ready");
        assert_eq!(s2.as_deref(), Some("FTP"));
    }
}
