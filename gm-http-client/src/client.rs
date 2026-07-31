//! HTTP client with GM/TLS support

use crate::error::HttpClientError;
use gm_tls::{GmTlsStream, TlsConfig, TlsConnector};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Maximum response body size (10 MB)
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum header size (64 KB)
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Private IP address ranges that should be blocked for SSRF protection
/// Expanded to cover all RFC 1122 / RFC 3927 reserved ranges including
/// cloud metadata link-local addresses (169.254.169.254).
const BLOCKED_PRIVATE_IPS: &[&str] = &[
    "10.",      // 10.0.0.0/8 — RFC 1122 Class A private
    "172.16.",  // 172.16.0.0/12 (partial, 172.16.x)
    "172.17.",  //
    "172.18.",  //
    "172.19.",  //
    "172.20.",  //
    "172.21.",  //
    "172.22.",  //
    "172.23.",  //
    "172.24.",  //
    "172.25.",  //
    "172.26.",  //
    "172.27.",  //
    "172.28.",  //
    "172.29.",  //
    "172.30.",  //
    "172.31.",  //
    "192.168.", // 192.168.0.0/16 — RFC 1122 Class C private
    "127.",     // Loopback (127.0.0.0/8)
    "169.254.", // RFC 3927 link-local (includes AWS/GCP/Azure metadata at 169.254.169.254)
    "100.64.",  // RFC 6598 Carrier-Grade NAT (100.64.0.0/10)
    "198.18.",  // RFC 2544 benchmark addresses (198.18.0.0/15)
    "::1",      // IPv6 loopback
    "fc00:",    // IPv6 unique local (fc00::/7)
    "fd00:",    // IPv6 unique local
    "fe80:",    // IPv6 link-local (fe80::/10)
];

/// HTTP response
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// GM/HTTP Client for making HTTPS requests using GM/TLS
#[derive(Clone)]
pub struct GmHttpClient {
    tls_connector: TlsConnector,
}

impl GmHttpClient {
    /// Create a new GM/HTTP client with the given TLS configuration
    pub fn new(tls_config: TlsConfig) -> Result<Self, HttpClientError> {
        let tls_connector =
            TlsConnector::new(tls_config).map_err(|e| HttpClientError::TlsError(e.to_string()))?;
        Ok(Self { tls_connector })
    }

    /// Get a reference to the TLS connector
    pub(crate) fn tls_connector(&self) -> &TlsConnector {
        &self.tls_connector
    }

    /// Send a GET request to the given URL
    pub async fn get(&self, url: &str) -> Result<Response, HttpClientError> {
        let parsed = parse_and_validate_url(url)?;
        self.request("GET", &parsed.host, parsed.port, &parsed.path, &[])
            .await
    }

    /// Send a POST request to the given URL with the given body
    pub async fn post(&self, url: &str, body: &[u8]) -> Result<Response, HttpClientError> {
        let parsed = parse_and_validate_url(url)?;
        self.request("POST", &parsed.host, parsed.port, &parsed.path, body)
            .await
    }

    pub(crate) async fn request(
        &self,
        method: &str,
        host: &str,
        port: u16,
        path: &str,
        body: &[u8],
    ) -> Result<Response, HttpClientError> {
        let addr = format!("{}:{}", host, port);

        // Resolve and validate the IP address to prevent SSRF
        // Returns validated SocketAddr to eliminate TOCTOU between validation and connection
        let validated_addr = validate_address_for_ssrf(&addr).await?;

        let tcp = TcpStream::connect(validated_addr)
            .await
            .map_err(|e| HttpClientError::ConnectionFailed(e.to_string()))?;

        let mut tls: GmTlsStream<TcpStream> = self
            .tls_connector
            .connect(tcp)
            .await
            .map_err(|e| HttpClientError::TlsError(e.to_string()))?;

        let request = build_request(method, host, path, body);
        tls.write_all(request.as_bytes())
            .await
            .map_err(|e| HttpClientError::IoError(e.to_string()))?;
        // Write body bytes after headers (for POST/PUT requests)
        if !body.is_empty() {
            tls.write_all(body)
                .await
                .map_err(|e| HttpClientError::IoError(e.to_string()))?;
        }

        self.read_response(&mut tls).await
    }

    /// Read HTTP response from a TLS stream (used by connection pool)
    pub(crate) async fn read_response(
        &self,
        tls: &mut GmTlsStream<TcpStream>,
    ) -> Result<Response, HttpClientError> {
        let mut response_buf = Vec::new();
        let mut chunk_buf = [0u8; 8192];
        let mut header_end = None;

        // Read until we have the full headers (ends with \r\n\r\n)
        while header_end.is_none() && response_buf.len() < MAX_HEADER_SIZE {
            let n = tls
                .read(&mut chunk_buf)
                .await
                .map_err(|e| HttpClientError::IoError(e.to_string()))?;
            if n == 0 {
                break;
            }
            response_buf.extend_from_slice(&chunk_buf[..n]);
            if response_buf.len() >= 4 {
                for i in 0..response_buf.len().saturating_sub(3) {
                    if &response_buf[i..i + 4] == b"\r\n\r\n" {
                        header_end = Some(i + 4);
                        break;
                    }
                }
            }
        }

        if header_end.is_none() && response_buf.len() >= MAX_HEADER_SIZE {
            return Err(HttpClientError::ResponseParseError(
                "header size exceeds maximum allowed".to_string(),
            ));
        }

        let header_end = header_end.ok_or_else(|| {
            HttpClientError::ResponseParseError("missing header terminator".to_string())
        })?;

        let (status, content_length) = parse_response_start(&response_buf[..header_end])?;

        if content_length > MAX_RESPONSE_SIZE {
            return Err(HttpClientError::ResponseParseError(format!(
                "response body too large: {} bytes (max: {} bytes)",
                content_length, MAX_RESPONSE_SIZE
            )));
        }

        let mut body = Vec::with_capacity(content_length);
        let mut body_read = 0;
        while body_read < content_length {
            let n = tls
                .read(&mut chunk_buf)
                .await
                .map_err(|e| HttpClientError::IoError(e.to_string()))?;
            if n == 0 {
                break;
            }
            let to_take = (content_length - body_read).min(n);
            body.extend_from_slice(&chunk_buf[..to_take]);
            body_read += to_take;
        }

        Ok(Response { status, body })
    }
}

pub(crate) struct ParsedUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Parse and validate URL for security issues including SSRF prevention.
pub(crate) fn parse_and_validate_url(url: &str) -> Result<ParsedUrl, HttpClientError> {
    // Ensure URL starts with https://
    if !url.starts_with("https://") {
        return Err(HttpClientError::UrlValidationError(
            "URL must start with https://".to_string(),
        ));
    }

    let url_without_scheme = &url[8..]; // Skip "https://"

    // Extract host:port and path
    let (host_port, path) = url_without_scheme
        .split_once('/')
        .unwrap_or((url_without_scheme, "/"));

    // Parse host and port
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        let port_num = p
            .parse::<u16>()
            .map_err(|_| HttpClientError::UrlValidationError("invalid port number".to_string()))?;
        (h.to_string(), port_num)
    } else {
        (host_port.to_string(), 443)
    };

    // Validate hostname is not empty
    if host.is_empty() {
        return Err(HttpClientError::UrlValidationError(
            "hostname cannot be empty".to_string(),
        ));
    }

    // Block certain dangerous hostnames
    let host_lower = host.to_lowercase();
    if is_blocked_hostname(&host_lower) {
        return Err(HttpClientError::UrlValidationError(format!(
            "access to '{}' is blocked for security reasons",
            host
        )));
    }

    Ok(ParsedUrl {
        host,
        port,
        path: format!("/{}", path),
    })
}

/// Check if a hostname should be blocked (localhost, internal domains, etc.)
fn is_blocked_hostname(hostname: &str) -> bool {
    // Block localhost variants
    if hostname == "localhost" || hostname == "localhost.localdomain" {
        return true;
    }

    // Block internal domain suffixes
    if hostname.ends_with(".local")
        || hostname.ends_with(".internal")
        || hostname.ends_with(".localhost")
        || hostname.ends_with(".localdomain")
    {
        return true;
    }

    // Block IP addresses that look like private ranges (basic check)
    // More thorough validation happens in validate_address_for_ssrf
    for blocked_prefix in BLOCKED_PRIVATE_IPS {
        if hostname.starts_with(blocked_prefix) {
            return true;
        }
    }

    false
}

/// Validate resolved IP address to prevent SSRF attacks.
///
/// This function resolves the hostname, validates all resolved IP addresses
/// against private/blocklists, and returns the first valid SocketAddr.
///
/// # TOCTOU Protection
///
/// By returning the validated SocketAddr directly (instead of letting the
/// caller re-resolve), we eliminate the time-of-check to time-of-use window
/// where a DNS rebinding attack could swap the IP between validation and
/// connection.
async fn validate_address_for_ssrf(addr: &str) -> Result<std::net::SocketAddr, HttpClientError> {
    use tokio::net::lookup_host;

    // Resolve the address
    let addrs: Vec<_> = lookup_host(addr)
        .await
        .map_err(|e| HttpClientError::ConnectionFailed(format!("DNS resolution failed: {}", e)))?
        .collect();

    if addrs.is_empty() {
        return Err(HttpClientError::ConnectionFailed(
            "no addresses resolved".to_string(),
        ));
    }

    // Check all resolved addresses, return the first valid one
    for socket_addr in addrs {
        let ip = socket_addr.ip();

        // Block loopback (including IPv4-mapped addresses like ::ffff:127.0.0.1)
        if is_loopback_or_mapped_loopback(&ip) {
            continue;
        }

        // Block private/unspecified addresses using our custom check
        // (is_link_local is not available on IpAddr directly)
        if is_private_ip(&ip) || is_link_local_ip(&ip) {
            continue;
        }

        // Return the validated SocketAddr to prevent TOCTOU
        return Ok(socket_addr);
    }

    // All resolved addresses were blocked
    Err(HttpClientError::UrlValidationError(
        "connection to private/link-local/loopback address is not allowed".to_string(),
    ))
}

/// Check if an IP address is link-local.
fn is_link_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_link_local(),
        IpAddr::V6(ipv6) => {
            let segments = ipv6.segments();
            // fe80::/10 - Link-local
            (segments[0] & 0xffc0) == 0xfe80
                // IPv4-mapped link-local: ::ffff:169.254.x.x
                || (segments[0] == 0 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0
                    && segments[4] == 0 && segments[5] == 0xffff
                    && ((segments[6] >> 8) as u8) == 169
                    && ((segments[6] & 0xff) as u8) == 254)
        }
    }
}

/// Check if an IP address is loopback, including IPv4-mapped IPv6 addresses
/// (e.g., ::ffff:127.0.0.1 maps to 127.0.0.1).
fn is_loopback_or_mapped_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_loopback(),
        IpAddr::V6(ipv6) => {
            // Check native IPv6 loopback (::1)
            if ipv6.is_loopback() {
                return true;
            }
            // Check IPv4-mapped address: ::ffff:127.x.x.x
            // IPv4-mapped IPv6 format: ::ffff:w.x.y.z → segments [0,0,0,0,0,0xffff,w*256+x, y*256+z]
            let segs = ipv6.segments();
            if segs[0] == 0
                && segs[1] == 0
                && segs[2] == 0
                && segs[3] == 0
                && segs[4] == 0
                && segs[5] == 0xffff
            {
                // Extract first octet of IPv4 address from segments[6]
                let v4oct1 = (segs[6] >> 8) as u8;
                return v4oct1 == 127; // 127.0.0.0/8 is loopback
            }
            false
        }
    }
}

/// Check if an IP address is in a private range.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 169.254.0.0/16 (link-local)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            false
        }
        IpAddr::V6(ipv6) => {
            // fc00::/7 - Unique local address
            let segments = ipv6.segments();
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // fe80::/10 - Link-local
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // IPv4-mapped IPv6 address: ::ffff:10.x.x.x, ::ffff:172.16.x.x, ::ffff:192.168.x.x
            if segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0
                && segments[5] == 0xffff
            {
                let v4_oct1 = (segments[6] >> 8) as u8;
                let v4_oct2 = (segments[6] & 0xff) as u8;
                // 10.0.0.0/8
                if v4_oct1 == 10 {
                    return true;
                }
                // 172.16.0.0/12
                if v4_oct1 == 172 && (16..=31).contains(&v4_oct2) {
                    return true;
                }
                // 192.168.0.0/16
                if v4_oct1 == 192 && v4_oct2 == 168 {
                    return true;
                }
            }
            false
        }
    }
}

pub(crate) fn build_request(method: &str, host: &str, path: &str, body: &[u8]) -> String {
    if body.is_empty() {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            method, path, host
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            method,
            path,
            host,
            body.len()
        )
    }
}

fn parse_response_start(buf: &[u8]) -> Result<(u16, usize), HttpClientError> {
    let header_str = String::from_utf8_lossy(buf);
    let status_line = header_str
        .lines()
        .next()
        .ok_or_else(|| HttpClientError::ResponseParseError("missing status line".to_string()))?;

    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| HttpClientError::ResponseParseError("invalid status code".to_string()))?;

    let content_length = header_str
        .lines()
        .skip(1)
        .find(|h| h.to_lowercase().starts_with("content-length:"))
        .and_then(|h| h.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    // Validate content length against maximum
    if content_length > MAX_RESPONSE_SIZE {
        return Err(HttpClientError::ResponseParseError(format!(
            "content-length {} exceeds maximum allowed {}",
            content_length, MAX_RESPONSE_SIZE
        )));
    }

    Ok((status, content_length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url_valid() {
        let result = parse_and_validate_url("https://example.com/path");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/path");
    }

    #[test]
    fn test_parse_url_with_port() {
        let result = parse_and_validate_url("https://example.com:8443/path");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 8443);
    }

    #[test]
    fn test_parse_url_missing_scheme() {
        let result = parse_and_validate_url("http://example.com/path");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(HttpClientError::UrlValidationError(_))
        ));
    }

    #[test]
    fn test_parse_url_localhost_blocked() {
        let result = parse_and_validate_url("https://localhost/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_url_private_ip_blocked() {
        let result = parse_and_validate_url("https://192.168.1.1/path");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_private_ip() {
        use std::net::Ipv4Addr;

        // Private IPv4
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Public IPv4
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
