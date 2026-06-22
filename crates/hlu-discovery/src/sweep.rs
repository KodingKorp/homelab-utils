//! Bounded asynchronous TCP connect sweep.
//!
//! This is the privilege-free liveness probe: for each (host, port) we attempt a TCP connect
//! under a timeout. Any successful connect both marks the host alive and records an open port
//! (a cheap role fingerprint). Concurrency is capped with a semaphore so a `/24 × N-ports`
//! fan-out never exhausts file descriptors or ephemeral ports.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Connect-scan `hosts × ports`, returning the open ports observed per responsive host.
pub async fn tcp_sweep(
    hosts: &[Ipv4Addr],
    ports: &[u16],
    concurrency: usize,
    timeout: Duration,
) -> HashMap<IpAddr, Vec<u16>> {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = JoinSet::new();

    for &host in hosts {
        for &port in ports {
            let semaphore = semaphore.clone();
            tasks.spawn(async move {
                let _permit = semaphore.acquire_owned().await.ok()?;
                let addr = SocketAddr::new(IpAddr::V4(host), port);
                match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(_stream)) => Some((IpAddr::V4(host), port)),
                    _ => None,
                }
            });
        }
    }

    let mut open: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some((ip, port))) = result {
            open.entry(ip).or_default().push(port);
        }
    }
    for ports in open.values_mut() {
        ports.sort_unstable();
        ports.dedup();
    }
    open
}
