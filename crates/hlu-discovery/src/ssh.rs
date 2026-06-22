//! SSH detection via a raw, handshake-free TCP banner read.
//!
//! Per RFC 4253 §4.2 an SSH server sends its `SSH-2.0-...` identification string immediately on
//! connect, before any key exchange. So we only need to connect and read the first line — no SSH
//! crate, no auth, no negotiation. A bare TCP connect proves the port is *reachable*; only the
//! `SSH-` prefix proves the host actually speaks SSH.

use hlu_core::SshStatus;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Outcome of an SSH banner probe.
#[derive(Debug, Clone)]
pub struct SshProbeResult {
    /// Distinct reachability/confirmation state.
    pub status: SshStatus,
    /// The identification banner, when one was read.
    pub banner: Option<String>,
    /// Best-effort OS hint: the banner's trailing comment (e.g. `Ubuntu-3ubuntu0.1`).
    pub os_hint: Option<String>,
}

/// Probe `ip:port` for SSH within `timeout` (applied to both connect and the banner read).
pub async fn probe(ip: IpAddr, port: u16, timeout: Duration) -> SshProbeResult {
    let addr = SocketAddr::new(ip, port);

    let mut stream = match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => stream,
        _ => {
            return SshProbeResult {
                status: SshStatus::Unreachable,
                banner: None,
                os_hint: None,
            };
        }
    };

    // The identification string is CRLF-terminated and capped at 255 bytes (RFC 4253 §4.2).
    let mut buf = [0u8; 255];
    match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => parse_banner(&buf[..n]),
        // Connected but said nothing readable: port is reachable, but unconfirmed as SSH.
        _ => SshProbeResult {
            status: SshStatus::PortReachable,
            banner: None,
            os_hint: None,
        },
    }
}

fn parse_banner(bytes: &[u8]) -> SshProbeResult {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().next().unwrap_or("").trim();

    if let Some(rest) = line.strip_prefix("SSH-") {
        // `rest` is like `2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1`; the comment after the first
        // space is the most useful OS hint.
        let os_hint = rest
            .split_once(' ')
            .map(|(_, comment)| comment.trim().to_string())
            .filter(|c| !c.is_empty());
        SshProbeResult {
            status: SshStatus::ConfirmedSsh,
            banner: Some(line.to_string()),
            os_hint,
        }
    } else {
        SshProbeResult {
            status: SshStatus::PortReachable,
            banner: None,
            os_hint: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirms_ssh_and_extracts_os_hint() {
        let r = parse_banner(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1\r\n");
        assert_eq!(r.status, SshStatus::ConfirmedSsh);
        assert_eq!(
            r.banner.as_deref(),
            Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu0.1")
        );
        assert_eq!(r.os_hint.as_deref(), Some("Ubuntu-3ubuntu0.1"));
    }

    #[test]
    fn non_ssh_banner_is_only_port_reachable() {
        let r = parse_banner(b"220 smtp.example.com ESMTP\r\n");
        assert_eq!(r.status, SshStatus::PortReachable);
        assert!(r.banner.is_none());
    }

    #[test]
    fn ssh_without_comment_has_no_os_hint() {
        let r = parse_banner(b"SSH-2.0-OpenSSH_9.6p1\r\n");
        assert_eq!(r.status, SshStatus::ConfirmedSsh);
        assert!(r.os_hint.is_none());
    }
}
