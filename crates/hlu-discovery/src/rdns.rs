//! Reverse-DNS (PTR) name resolution, bounded by a short timeout.

use std::net::IpAddr;
use std::time::Duration;

const RDNS_TIMEOUT: Duration = Duration::from_millis(1500);

/// Resolve the PTR name for `ip`, or `None` if there is none (or it merely echoes the IP, which
/// some resolvers do on failure). Runs on the blocking pool and is time-bounded so a slow or
/// missing resolver never stalls a scan.
pub async fn reverse_dns(ip: IpAddr) -> Option<String> {
    let handle = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok());
    let name = match tokio::time::timeout(RDNS_TIMEOUT, handle).await {
        Ok(Ok(name)) => name,
        _ => None,
    };
    name.filter(|n| n != &ip.to_string())
}
