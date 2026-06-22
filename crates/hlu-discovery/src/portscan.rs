//! Deep TCP port scanning with best-effort service/application identification.
//!
//! Two phases: (1) a bounded connect-scan over the requested port range finds *open* ports
//! cheaply; (2) only those few open ports are then probed for a service banner (passive read,
//! falling back to a minimal HTTP request — many homelab apps are web UIs that send nothing
//! until asked). This keeps a full 1–65535 sweep affordable while still naming what's running.
//!
//! Identification has two layers: the protocol/role (`service`: HTTP, HTTPS, SSH…) and the
//! concrete application (`product`: Grafana, Proxmox VE, OpenSSH…) plus a `version` and web
//! `title` when derivable. Web UIs are probed over both plaintext and TLS (self-signed certs are
//! the homelab norm), the HTML `<title>` is read, and a small fingerprint table maps
//! title/header/cookie signals to known products.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hlu_core::ServicePort;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};

/// A curated set of common homelab/service ports for a fast (non-full) scan.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465, 587, 631, 993, 995,
    1080, 1433, 1521, 1883, 1900, 2049, 2179, 2375, 2376, 3000, 3001, 3128, 3306, 3389, 4000, 4317,
    4318, 5000, 5001, 5060, 5201, 5432, 5601, 5900, 5901, 6379, 7878, 8000, 8006, 8080, 8081, 8086,
    8096, 8123, 8443, 8888, 8920, 9000, 9090, 9091, 9100, 9200, 9411, 9443, 11434, 15672, 16686,
    19999, 25565, 27017, 32400, 51820,
];

/// Hard upper bound on the whole per-port identification: connect + handshake + reads. A host that
/// accepts the TCP connect then goes silent (never completes a TLS handshake, never sends headers,
/// trickles a body forever) can otherwise leave the scan — and the UI — hanging. Every probe task
/// is wrapped in this deadline so a stalled port resolves to a partial result instead of blocking.
const PROBE_BUDGET: Duration = Duration::from_secs(2);

/// Maximum bytes read from an HTTP response while hunting for the `<title>`.
const HTTP_READ_CAP: usize = 16 * 1024;

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
            // Hard per-port deadline so one stalled host can never wedge the scan or the UI.
            match tokio::time::timeout(PROBE_BUDGET, identify(ip, port, banner_timeout)).await {
                Ok(service) => service,
                Err(_) => ServicePort {
                    port,
                    service: well_known(port).map(str::to_string),
                    ..Default::default()
                },
            }
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
/// it with any banner the server volunteers, and fall back to an HTTP(S) probe that reads the page
/// title and fingerprints the application.
async fn identify(ip: IpAddr, port: u16, timeout: Duration) -> ServicePort {
    let mut sp = ServicePort {
        port,
        service: well_known(port).map(str::to_string),
        ..Default::default()
    };

    let addr = SocketAddr::new(ip, port);
    let Ok(Ok(mut stream)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await else {
        return sp;
    };

    // TLS web UIs (Proxmox, anything on 443/8443/9443) stay silent until they receive a
    // ClientHello, so there's nothing to read passively — handshake, then probe over TLS.
    if is_tls_port(port) {
        if let Some(mut tls) = tls_handshake(stream, ip, timeout).await {
            if let Some(http) = http_probe(&mut tls, ip, timeout).await {
                sp.service.get_or_insert_with(|| "HTTPS".to_string());
                apply_http(&mut sp, http);
            }
        }
        return sp;
    }

    // Many protocols (SSH, FTP, SMTP, Redis, …) send a banner immediately on connect.
    let mut buf = [0u8; 256];
    let read = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut buf)).await;
    if let Ok(Ok(n)) = read {
        if n > 0 {
            let line = first_line(&buf[..n]);
            if !line.is_empty() {
                refine_service(&mut sp.service, &line);
                banner_product(&line, &mut sp.product, &mut sp.version);
                sp.banner = Some(line);
            }
        }
    }

    // No spontaneous banner: try plaintext HTTP, then — if that says nothing — HTTPS on a fresh
    // connection. Covers web UIs / REST APIs, including those served over TLS on a non-standard port.
    if sp.banner.is_none() {
        if let Some(http) = http_probe(&mut stream, ip, timeout).await {
            sp.service.get_or_insert_with(|| "HTTP".to_string());
            apply_http(&mut sp, http);
        } else if let Ok(Ok(retry)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await
        {
            if let Some(mut tls) = tls_handshake(retry, ip, timeout).await {
                if let Some(http) = http_probe(&mut tls, ip, timeout).await {
                    sp.service.get_or_insert_with(|| "HTTPS".to_string());
                    apply_http(&mut sp, http);
                }
            }
        }
    }

    // Last resort: the ephemeral/dynamic range (Windows RPC, transient services) — name the range
    // rather than leaving it blank when nothing else identified it.
    if sp.service.is_none() && port >= 49152 {
        sp.service = Some("Dynamic/RPC".to_string());
    }

    sp
}

/// Fold an HTTP probe result into the service record. A confident fingerprint match wins over the
/// port-based product guess; otherwise the `Server:` header product/version are used as a fallback.
fn apply_http(sp: &mut ServicePort, http: HttpProbe) {
    let fingerprinted = fingerprint(&http).map(|fp| fp.product.to_string());
    sp.banner = Some(http.summary);
    if http.title.is_some() {
        sp.title = http.title;
    }
    match fingerprinted {
        Some(product) => {
            sp.product = Some(product);
            if sp.version.is_none() {
                sp.version = http.server_version;
            }
        }
        None => {
            if sp.product.is_none() {
                sp.product = http.server_product;
            }
            if sp.version.is_none() {
                sp.version = http.server_version;
            }
        }
    }
}

/// Ports we treat as TLS-first: connect, handshake, then speak HTTP over the encrypted stream.
fn is_tls_port(port: u16) -> bool {
    matches!(port, 443 | 8443 | 9443 | 8006)
}

fn first_line(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let line = text.lines().next().unwrap_or("").trim();
    line.chars().take(120).collect()
}

// ---- TLS ----------------------------------------------------------------------------------------

/// A certificate verifier that accepts anything.
///
/// Homelab services overwhelmingly present self-signed certs, and this tool is a *passive LAN
/// inventory reader* — it only reads banners/titles, never sends credentials or trusts the host
/// for anything. Verification would just block identification of the exact devices we care about,
/// so it is intentionally disabled. This must never be reused for an authenticated client.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A process-wide TLS connector. Built once: rustls 0.23 requires an explicit crypto provider
/// (otherwise `ClientConfig::builder()` panics with "no process-level CryptoProvider available"),
/// and a library should not mutate process-global provider state — so the ring provider is passed
/// in directly.
fn tls_connector() -> &'static TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR.get_or_init(|| {
        let config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    })
}

/// Perform a TLS handshake over an already-connected TCP stream, bounded by `timeout`.
async fn tls_handshake(
    stream: TcpStream,
    ip: IpAddr,
    timeout: Duration,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::IpAddress(ip.into());
    let connect = tls_connector().connect(server_name, stream);
    match tokio::time::timeout(timeout, connect).await {
        Ok(Ok(tls)) => Some(tls),
        _ => None,
    }
}

// ---- HTTP probing -------------------------------------------------------------------------------

/// Parsed signals from an HTTP(S) response, used for display and fingerprinting.
struct HttpProbe {
    /// `"<status> · <server>"` summary (unchanged format), shown as the banner.
    summary: String,
    /// HTML `<title>`, normalized and length-capped.
    title: Option<String>,
    /// Product parsed from the `Server:` header (e.g. "nginx").
    server_product: Option<String>,
    /// Version parsed from the `Server:` header (e.g. "1.25.3").
    server_version: Option<String>,
    /// Raw `Server:` header value.
    server_header: Option<String>,
    /// `X-Powered-By` header value.
    powered_by: Option<String>,
    /// Names (not values) of any `Set-Cookie` cookies.
    cookie_names: Vec<String>,
    /// `WWW-Authenticate` header value (often carries a realm).
    www_authenticate: Option<String>,
}

/// Send a minimal HTTP request and read enough of the reply to capture headers and the `<title>`.
///
/// Reads into a growing buffer (capped at [`HTTP_READ_CAP`]) under one overall `timeout`, stopping
/// early on EOF, the cap, or once both the header terminator and a closing `</title>` have arrived.
/// Generic over the stream so the same code serves plaintext TCP and TLS.
async fn http_probe<S>(stream: &mut S, ip: IpAddr, timeout: Duration) -> Option<HttpProbe>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request =
        format!("GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: homelab-utils\r\nAccept: */*\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;

    let deadline = Instant::now() + timeout;
    let mut data: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(d) if !d.is_zero() => d,
            _ => break,
        };
        match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => break, // EOF (HTTP/1.0 closes after the response)
            Ok(Ok(n)) => {
                data.extend_from_slice(&chunk[..n]);
                if data.len() >= HTTP_READ_CAP {
                    break;
                }
                if has_subsequence(&data, b"\r\n\r\n") && contains_ci(&data, b"</title>") {
                    break;
                }
            }
            _ => break, // read error or per-loop timeout
        }
    }

    if data.is_empty() {
        return None;
    }
    parse_http_probe(&data)
}

/// Summarize an HTTP response as `"<status> · <server>"` (or just the status), or `None` if the
/// reply isn't HTTP. Kept stable as the human-readable banner.
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

/// Parse the full set of fingerprinting signals out of an HTTP response.
fn parse_http_probe(bytes: &[u8]) -> Option<HttpProbe> {
    let summary = parse_http(bytes)?; // also enforces the leading "HTTP/" check
    let text = String::from_utf8_lossy(bytes);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));

    let mut server_header = None;
    let mut powered_by = None;
    let mut www_authenticate = None;
    let mut cookie_names = Vec::new();

    for line in head.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => server_header = nonempty(value),
            "x-powered-by" => powered_by = nonempty(value),
            "www-authenticate" => www_authenticate = nonempty(value),
            "set-cookie" => {
                // The cookie name is everything before the first '=' or ';'.
                if let Some(name) = value.split(['=', ';']).next() {
                    if let Some(name) = nonempty(name) {
                        cookie_names.push(name);
                    }
                }
            }
            _ => {}
        }
    }

    let (server_product, server_version) = server_header
        .as_deref()
        .map(first_token)
        .map(split_product_version)
        .unwrap_or((None, None));

    Some(HttpProbe {
        summary,
        title: extract_title(body),
        server_product,
        server_version,
        server_header,
        powered_by,
        cookie_names,
        www_authenticate,
    })
}

/// Extract and normalize the HTML `<title>`: case-insensitive, attribute-tolerant, with a few
/// common entities decoded, whitespace collapsed, and length capped. No HTML-parser dependency.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let open = lower.find("<title")?;
    let content_start = open + lower[open..].find('>')? + 1;
    let content_end = content_start + lower[content_start..].find("</title>")?;
    let collapsed = collapse_whitespace(&decode_entities(&body[content_start..content_end]));
    if collapsed.is_empty() {
        None
    } else {
        Some(collapsed.chars().take(120).collect())
    }
}

/// Decode the handful of HTML entities that show up in titles. `&amp;` is decoded last so an
/// already-decoded `<`/`>` isn't re-interpreted.
fn decode_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn nonempty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn first_token(s: &str) -> &str {
    s.split_whitespace().next().unwrap_or(s)
}

/// Split a `Name/1.2.3`, `Name_1.2.3`, or `Name 1.2.3` token into `(product, version)`.
fn split_product_version(token: &str) -> (Option<String>, Option<String>) {
    let token = token.trim();
    if token.is_empty() {
        return (None, None);
    }
    if let Some(idx) = token.find(['/', '_', ' ']) {
        let (name, rest) = token.split_at(idx);
        return (nonempty(name), version_prefix(&rest[1..]));
    }
    (nonempty(token), None)
}

/// Take the leading version-looking run (must start with a digit), e.g. "9.6p1", "1.25.3".
fn version_prefix(s: &str) -> Option<String> {
    let s = s.trim();
    if !s.chars().next()?.is_ascii_digit() {
        return None;
    }
    let v: String = s
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
        .collect();
    nonempty(v.trim_end_matches(['.', '-']))
}

// ---- application fingerprints -------------------------------------------------------------------

/// A signal-based fingerprint: a match on *any* non-empty signal list (case-insensitive substring)
/// identifies the product. Order the table most-specific first; the first match wins.
struct Fingerprint {
    product: &'static str,
    title_has: &'static [&'static str],
    server_has: &'static [&'static str],
    cookie_has: &'static [&'static str],
    powered_by_has: &'static [&'static str],
    www_auth_has: &'static [&'static str],
}

const fn fp(
    product: &'static str,
    title_has: &'static [&'static str],
    server_has: &'static [&'static str],
    cookie_has: &'static [&'static str],
    powered_by_has: &'static [&'static str],
    www_auth_has: &'static [&'static str],
) -> Fingerprint {
    Fingerprint {
        product,
        title_has,
        server_has,
        cookie_has,
        powered_by_has,
        www_auth_has,
    }
}

/// Known homelab applications keyed by HTTP signals. All needles are lowercase.
///
/// Note: shared session cookies (JSESSIONID/PHPSESSID/SID) are deliberately *not* used as primary
/// signals — they identify a framework, not an app, and would mislabel. Where a cookie is listed it
/// is product-specific (e.g. `pveauthcookie`, `grafana_session`).
static FINGERPRINTS: &[Fingerprint] = &[
    fp(
        "Grafana",
        &["grafana"],
        &[],
        &["grafana_session", "grafana_sess"],
        &[],
        &[],
    ),
    fp(
        "Proxmox VE",
        &["proxmox"],
        &[],
        &["pveauthcookie"],
        &[],
        &[],
    ),
    fp("Home Assistant", &["home assistant"], &[], &[], &[], &[]),
    fp(
        "Portainer",
        &["portainer"],
        &[],
        &["portainer_api_key"],
        &[],
        &[],
    ),
    fp("Jellyfin", &["jellyfin"], &["jellyfin"], &[], &[], &[]),
    fp("Plex", &["plex"], &["plex media server"], &[], &[], &[]),
    fp("Pi-hole", &["pi-hole"], &[], &[], &[], &[]),
    fp(
        "AdGuard Home",
        &["adguard home", "adguardhome"],
        &[],
        &[],
        &[],
        &[],
    ),
    fp(
        "Nginx Proxy Manager",
        &["nginx proxy manager"],
        &[],
        &[],
        &[],
        &[],
    ),
    fp("TrueNAS", &["truenas"], &[], &[], &[], &[]),
    fp(
        "Synology DSM",
        &["synology", "diskstation"],
        &[],
        &[],
        &[],
        &["syno"],
    ),
    fp("Uptime Kuma", &["uptime kuma"], &[], &[], &[], &[]),
    fp("Sonarr", &["sonarr"], &[], &[], &[], &[]),
    fp("Radarr", &["radarr"], &[], &[], &[], &[]),
    fp("qBittorrent", &["qbittorrent"], &[], &[], &[], &[]),
    fp(
        "Cockpit",
        &["cockpit"],
        &["cockpit"],
        &["cockpit"],
        &[],
        &[],
    ),
    fp(
        "Prometheus",
        &["prometheus time series", "prometheus"],
        &[],
        &[],
        &[],
        &[],
    ),
    fp("Traefik", &["traefik"], &[], &[], &[], &[]),
    fp("Jenkins", &["jenkins"], &[], &[], &["jenkins"], &[]),
    fp(
        "Nextcloud",
        &["nextcloud"],
        &[],
        &["nc_sessionid", "oc_sessionpassphrase"],
        &[],
        &[],
    ),
    fp(
        "Vaultwarden",
        &["vaultwarden", "bitwarden"],
        &[],
        &[],
        &[],
        &[],
    ),
    fp("Jaeger", &["jaeger"], &[], &[], &[], &[]),
    // Web frameworks — least specific, matched only via X-Powered-By, so they sit last and only
    // win when no application above matched. They name the stack when the app itself is opaque
    // (e.g. a bare REST/API server that just 404s on `/`).
    fp("Next.js", &[], &[], &[], &["next.js"], &[]),
    fp("Express", &[], &[], &[], &["express"], &[]),
    fp("ASP.NET", &[], &[], &[], &["asp.net"], &[]),
    fp("PHP", &[], &[], &[], &["php/"], &[]),
];

/// Return the first fingerprint whose signals match the response, if any.
fn fingerprint(h: &HttpProbe) -> Option<&'static Fingerprint> {
    let title = h.title.as_deref().unwrap_or_default().to_ascii_lowercase();
    let server = h
        .server_header
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let powered = h
        .powered_by
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let www = h
        .www_authenticate
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cookies: Vec<String> = h
        .cookie_names
        .iter()
        .map(|c| c.to_ascii_lowercase())
        .collect();

    FINGERPRINTS.iter().find(|fp| {
        any_contains(&title, fp.title_has)
            || any_contains(&server, fp.server_has)
            || any_contains(&powered, fp.powered_by_has)
            || any_contains(&www, fp.www_auth_has)
            || fp
                .cookie_has
                .iter()
                .any(|needle| cookies.iter().any(|c| c.contains(*needle)))
    })
}

fn any_contains(haystack: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|n| !n.is_empty() && haystack.contains(*n))
}

// ---- banner-based product/version (non-web services) --------------------------------------------

/// Names of common services that may appear anywhere in a banner, with the canonical casing to show.
const KNOWN_PRODUCTS: &[&str] = &[
    "OpenSSH",
    "Dropbear",
    "ProFTPD",
    "vsFTPd",
    "Pure-FTPd",
    "FileZilla",
    "Postfix",
    "Exim",
    "Sendmail",
    "Dovecot",
    "nginx",
    "Apache",
    "lighttpd",
    "Caddy",
];

/// Best-effort product + version from a service banner. Only assigns when confident; leaves the
/// out-params untouched otherwise.
fn banner_product(banner: &str, product: &mut Option<String>, version: &mut Option<String>) {
    // SSH advertises its software explicitly: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5".
    if let Some(rest) = strip_prefix_ci(banner, "SSH-") {
        if let Some((_proto, software)) = rest.split_once('-') {
            let token = first_token(software);
            let (p, v) = split_product_version(token);
            assign(product, p);
            assign(version, v);
            return;
        }
    }

    // A named product anywhere in the greeting (FTP/SMTP/etc.).
    let lower = banner.to_ascii_lowercase();
    for name in KNOWN_PRODUCTS {
        let needle = name.to_ascii_lowercase();
        if let Some(pos) = lower.find(&needle) {
            assign(product, Some((*name).to_string()));
            // A version token usually follows the name: "ProFTPD 1.3.8", "(vsFTPd 3.0.5)".
            let after = &banner[pos + needle.len()..];
            let v = after
                .split([' ', '/', '_', '(', ')', ',', '\t'])
                .find_map(version_prefix);
            assign(version, v);
            return;
        }
    }

    // Generic "Name/1.2.3" token (high precision; avoids guessing on bare words).
    for token in banner.split([' ', '\t', '(', ')', ',']) {
        if token.contains('/') {
            if let (Some(p), Some(v)) = split_product_version(token) {
                assign(product, Some(p));
                assign(version, Some(v));
                return;
            }
        }
    }
}

fn assign(target: &mut Option<String>, value: Option<String>) {
    if let Some(v) = value {
        *target = Some(v);
    }
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

// ---- byte helpers -------------------------------------------------------------------------------

fn has_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Case-insensitive byte search; `needle` must already be lowercase.
fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack.windows(needle.len()).any(|w| {
            w.iter()
                .zip(needle)
                .all(|(b, n)| b.to_ascii_lowercase() == *n)
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
        2179 => "Hyper-V VMConnect",
        2375 | 2376 => "Docker API",
        // 3000 is ambiguous (Grafana, but also Node/Next/React dev servers) — don't assert an app;
        // a real Grafana is still identified by its title/cookie fingerprint.
        3000 => "HTTP",
        3128 => "Squid Proxy",
        3306 => "MySQL/MariaDB",
        3389 => "RDP",
        4317 => "OTLP/gRPC",
        4318 => "OTLP/HTTP",
        5000 | 5001 => "HTTP (dev)",
        5060 => "SIP",
        5201 => "iperf",
        5432 => "PostgreSQL",
        5601 => "Kibana",
        5900 | 5901 => "VNC",
        6379 => "Redis",
        7680 => "Windows Delivery Optimization",
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
        15672 => "RabbitMQ (mgmt)",
        16686 => "Jaeger",
        19999 => "Netdata",
        25565 => "Minecraft",
        27017 => "MongoDB",
        27036 => "Steam",
        32400 => "Plex",
        51820 => "WireGuard",
        _ => return None,
    };
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_probe() -> HttpProbe {
        HttpProbe {
            summary: String::new(),
            title: None,
            server_product: None,
            server_version: None,
            server_header: None,
            powered_by: None,
            cookie_names: Vec::new(),
            www_authenticate: None,
        }
    }

    #[test]
    fn well_known_names_common_ports() {
        assert_eq!(well_known(8006), Some("Proxmox VE"));
        assert_eq!(well_known(32400), Some("Plex"));
        assert_eq!(well_known(2179), Some("Hyper-V VMConnect"));
        assert_eq!(well_known(4317), Some("OTLP/gRPC"));
        assert_eq!(well_known(16686), Some("Jaeger"));
        // 3000 must not assert "Grafana" — it's ambiguous and identified by fingerprint instead.
        assert_eq!(well_known(3000), Some("HTTP"));
        assert_eq!(well_known(65000), None);
    }

    #[test]
    fn fingerprint_names_framework_via_powered_by() {
        let mut p = blank_probe();
        p.powered_by = Some("Next.js".into());
        assert_eq!(fingerprint(&p).map(|f| f.product), Some("Next.js"));

        // A specific app still wins over the generic framework signal.
        let mut p = blank_probe();
        p.title = Some("Grafana".into());
        p.powered_by = Some("Express".into());
        assert_eq!(fingerprint(&p).map(|f| f.product), Some("Grafana"));
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

    #[test]
    fn extract_title_basic_and_attributes() {
        assert_eq!(
            extract_title("<title>Grafana</title>").as_deref(),
            Some("Grafana")
        );
        assert_eq!(
            extract_title("<TITLE lang=\"en\">Proxmox Virtual Environment</TITLE>").as_deref(),
            Some("Proxmox Virtual Environment")
        );
    }

    #[test]
    fn extract_title_decodes_entities_and_collapses_whitespace() {
        assert_eq!(
            extract_title("<title>Tom &amp; Jerry &lt;3</title>").as_deref(),
            Some("Tom & Jerry <3")
        );
        assert_eq!(
            extract_title("<title>\n  Home\tAssistant  </title>").as_deref(),
            Some("Home Assistant")
        );
    }

    #[test]
    fn extract_title_absent_or_empty() {
        assert_eq!(extract_title("<html><body>no title</body></html>"), None);
        assert_eq!(extract_title("<title>   </title>"), None);
    }

    #[test]
    fn extract_title_caps_length() {
        let long = format!("<title>{}</title>", "x".repeat(200));
        assert_eq!(extract_title(&long).map(|t| t.chars().count()), Some(120));
    }

    #[test]
    fn split_product_version_handles_separators() {
        assert_eq!(
            split_product_version("nginx/1.25.3"),
            (Some("nginx".into()), Some("1.25.3".into()))
        );
        assert_eq!(
            split_product_version("OpenSSH_9.6p1"),
            (Some("OpenSSH".into()), Some("9.6p1".into()))
        );
        assert_eq!(
            split_product_version("cloudflare"),
            (Some("cloudflare".into()), None)
        );
    }

    #[test]
    fn banner_product_parses_ssh_and_ftp() {
        let mut p = None;
        let mut v = None;
        banner_product("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", &mut p, &mut v);
        assert_eq!(p.as_deref(), Some("OpenSSH"));
        assert_eq!(v.as_deref(), Some("9.6p1"));

        let (mut p, mut v) = (None, None);
        banner_product(
            "220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.2]",
            &mut p,
            &mut v,
        );
        assert_eq!(p.as_deref(), Some("ProFTPD"));
        assert_eq!(v.as_deref(), Some("1.3.8"));

        let (mut p, mut v) = (None, None);
        banner_product("220 (vsFTPd 3.0.5)", &mut p, &mut v);
        assert_eq!(p.as_deref(), Some("vsFTPd"));
        assert_eq!(v.as_deref(), Some("3.0.5"));

        let (mut p, mut v) = (None, None);
        banner_product("220 mail.example.com ESMTP Postfix", &mut p, &mut v);
        assert_eq!(p.as_deref(), Some("Postfix"));
        assert_eq!(v, None);
    }

    #[test]
    fn banner_product_leaves_unrelated_lines_untouched() {
        let mut p = None;
        let mut v = None;
        banner_product("* OK [CAPABILITY IMAP4rev1]", &mut p, &mut v);
        assert_eq!(p, None);
        assert_eq!(v, None);
    }

    #[test]
    fn fingerprint_matches_title_cookie_and_server() {
        let mut p = blank_probe();
        p.title = Some("Grafana".into());
        assert_eq!(fingerprint(&p).map(|f| f.product), Some("Grafana"));

        let mut p = blank_probe();
        p.cookie_names = vec!["PVEAuthCookie".into()];
        assert_eq!(fingerprint(&p).map(|f| f.product), Some("Proxmox VE"));

        let mut p = blank_probe();
        p.server_header = Some("Jellyfin".into());
        assert_eq!(fingerprint(&p).map(|f| f.product), Some("Jellyfin"));

        assert!(fingerprint(&blank_probe()).is_none());
    }

    #[test]
    fn parse_http_probe_extracts_title_headers_and_fingerprints() {
        let resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nSet-Cookie: PVEAuthCookie=abc123; path=/; secure\r\nContent-Type: text/html\r\n\r\n<html><head><title>Proxmox Virtual Environment</title></head></html>";
        let p = parse_http_probe(resp).unwrap();
        assert_eq!(p.title.as_deref(), Some("Proxmox Virtual Environment"));
        assert_eq!(p.server_product.as_deref(), Some("nginx"));
        assert_eq!(p.server_version.as_deref(), Some("1.25.3"));
        assert!(p.cookie_names.iter().any(|c| c == "PVEAuthCookie"));
        assert_eq!(fingerprint(&p).map(|f| f.product), Some("Proxmox VE"));
    }

    #[test]
    fn apply_http_prefers_fingerprint_over_server_header() {
        let mut sp = ServicePort {
            port: 3000,
            service: Some("HTTP".into()),
            ..Default::default()
        };
        let mut http = blank_probe();
        http.summary = "HTTP/1.1 302 Found · nginx".into();
        http.title = Some("Grafana".into());
        http.server_header = Some("nginx".into());
        http.server_product = Some("nginx".into());
        apply_http(&mut sp, http);
        assert_eq!(sp.product.as_deref(), Some("Grafana"));
        assert_eq!(sp.title.as_deref(), Some("Grafana"));
    }

    #[tokio::test]
    async fn http_probe_reads_title_split_across_reads() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let server_task = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server.read(&mut buf).await; // drain the request
            server
                .write_all(b"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html><head><ti")
                .await
                .unwrap();
            server
                .write_all(b"tle>Split Title</title></head></html>")
                .await
                .unwrap();
            drop(server); // EOF
        });

        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let probe = http_probe(&mut client, ip, Duration::from_millis(500))
            .await
            .unwrap();
        assert_eq!(probe.title.as_deref(), Some("Split Title"));
        server_task.await.unwrap();
    }
}
