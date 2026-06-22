//! Reading the operating system's ARP/neighbour cache (no elevated privileges required).
//!
//! After the TCP sweep has caused the OS to resolve MACs for responsive hosts, the cache is a
//! free source of IP→MAC mappings. We parse `/proc/net/arp` on Linux and the output of `arp -a`
//! elsewhere; both feed a tolerant tokeniser that extracts an IP and a MAC per line.

use std::collections::HashMap;
use std::net::IpAddr;

/// Read the ARP cache, returning `ip → canonical-lowercase-MAC`. Never errors: an unreadable
/// cache simply yields an empty map.
pub async fn read_arp_cache() -> HashMap<IpAddr, String> {
    tokio::task::spawn_blocking(read_arp_blocking)
        .await
        .unwrap_or_default()
}

fn read_arp_blocking() -> HashMap<IpAddr, String> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
            return parse_lines(&text);
        }
    }
    let output = std::process::Command::new("arp").arg("-a").output();
    match output {
        Ok(out) => parse_lines(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => HashMap::new(),
    }
}

/// Extract the first IP-like and first MAC-like token from each line. Handles `/proc/net/arp`
/// columns, Windows `arp -a` (dash-separated MACs), and macOS/BSD `arp -a` (`host (ip) at mac`).
fn parse_lines(text: &str) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let mut ip: Option<IpAddr> = None;
        let mut mac: Option<String> = None;
        for raw in line.split_whitespace() {
            let token = raw.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none() {
                if let Ok(parsed) = token.parse::<IpAddr>() {
                    ip = Some(parsed);
                    continue;
                }
            }
            if mac.is_none() {
                if let Some(normalized) = normalize_mac(token) {
                    mac = Some(normalized);
                }
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac) {
            if mac != "00:00:00:00:00:00" {
                map.insert(ip, mac);
            }
        }
    }
    map
}

/// Normalise a candidate MAC token (`aa-bb-..` or `aa:bb:..`) to canonical lowercase colon form,
/// or `None` if it is not a 6-octet hex MAC.
fn normalize_mac(token: &str) -> Option<String> {
    let lowered = token.replace('-', ":").to_ascii_lowercase();
    let parts: Vec<&str> = lowered.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    if parts
        .iter()
        .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        Some(lowered)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_proc_net_arp() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         a4:2b:b0:11:22:33     *        eth0\n\
                    192.168.1.55     0x1         0x2         00:00:00:00:00:00     *        eth0\n";
        let map = parse_lines(text);
        assert_eq!(
            map.get(&"192.168.1.1".parse::<IpAddr>().unwrap()).unwrap(),
            "a4:2b:b0:11:22:33"
        );
        // all-zero MAC (incomplete entry) is dropped
        assert!(!map.contains_key(&"192.168.1.55".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parses_windows_arp_dashes() {
        let text = "Interface: 192.168.1.10 --- 0x5\n  \
                    Internet Address      Physical Address      Type\n  \
                    192.168.1.1           a4-2b-b0-aa-bb-cc     dynamic\n";
        let map = parse_lines(text);
        assert_eq!(
            map.get(&"192.168.1.1".parse::<IpAddr>().unwrap()).unwrap(),
            "a4:2b:b0:aa:bb:cc"
        );
    }

    #[test]
    fn parses_macos_arp() {
        let text = "router (192.168.1.1) at a4:2b:b0:de:ad:be on en0 ifscope [ethernet]\n";
        let map = parse_lines(text);
        assert_eq!(
            map.get(&"192.168.1.1".parse::<IpAddr>().unwrap()).unwrap(),
            "a4:2b:b0:de:ad:be"
        );
    }
}
