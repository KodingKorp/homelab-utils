//! Determining which hosts to scan.
//!
//! For the privilege-free MVP we assume a `/24` around the machine's primary IPv4 address —
//! the overwhelmingly common homelab layout. Routed/multi-VLAN coverage is a later milestone;
//! callers can already pass an explicit host list via [`crate::ScanConfig::hosts`].

use std::net::{IpAddr, Ipv4Addr};

/// Derive `(self_ip, hosts)` for the `/24` containing the primary IPv4 address.
///
/// Returns `None` if no IPv4 address could be determined (e.g. IPv6-only host).
pub fn default_hosts() -> Option<(Ipv4Addr, Vec<Ipv4Addr>)> {
    let IpAddr::V4(local) = local_ip_address::local_ip().ok()? else {
        return None;
    };
    Some((local, hosts_in_24(local)))
}

/// All usable host addresses (`.1`–`.254`) of the `/24` containing `ip`.
pub fn hosts_in_24(ip: Ipv4Addr) -> Vec<Ipv4Addr> {
    let [a, b, c, _] = ip.octets();
    (1u8..=254).map(|h| Ipv4Addr::new(a, b, c, h)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_in_24_spans_full_range() {
        let hosts = hosts_in_24(Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }
}
