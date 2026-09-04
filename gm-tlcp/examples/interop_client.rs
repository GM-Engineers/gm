//! Standalone TLCP client for interop testing.
//!
//! Usage: interop_client PORT  SIGN_PUB_HEX  [SUITES_HEX_CSV]
//!
//! - PORT: TCP port of the TLCP server.
//! - SIGN_PUB_HEX: 130-character hex of the server's uncompressed SM2
//!   sign public key (65 bytes; leading 0x04).
//! - SUITES_HEX_CSV: optional comma-separated list of cipher suite IDs
//!   in hex (e.g. "e013,e003"). Defaults to all four TLCP suites.
//!
//! The `GMSSL_COMPAT` / `GM_TLCP_GMSSL_COMPAT` flag is a deprecated alias
//! kept for CLI compatibility. Historically it toggled a non-standard CBC
//! padding scheme to interop with pre-fix GmSSL; as of gm-tlcp 0.1.0 the
//! flag is a no-op because the CBC framing always follows RFC 5246
//! §6.2.3.2 / GB/T 38636-2020 §6.2.3.2, which is what current `gmssl
//! tlcp_server` (master, 3.3.0-dev.1183+) also follows. The flag will be
//! removed entirely in a future release.

use gm_tlcp::tlcp::{
    TLS_ECC_SM4_CBC_SM3, TLS_ECC_SM4_GCM_SM3, TLS_ECDHE_SM4_CBC_SM3, TLS_ECDHE_SM4_GCM_SM3,
    TlcpConnector,
};

const DEFAULT_DISTID: &str = "1234567812345678";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(52189);
    let sign_pub_hex = args.get(2).cloned().unwrap_or_default();
    let suites_arg = args.get(3).cloned();
    // CLI flag and env var are kept for backward compatibility but the
    // underlying flag is now a no-op: the wire format always follows
    // RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.
    let _compat_arg = args
        .get(4)
        .cloned()
        .or_else(|| std::env::var("GM_TLCP_GMSSL_COMPAT").ok())
        .unwrap_or_else(|| "1".to_string());

    let sign_pub = hex_decode(&sign_pub_hex)?;
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    eprintln!("[client] connecting to {}", addr);
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    eprintln!("[client] TCP connected");

    let offered: Vec<[u8; 2]> = match suites_arg {
        Some(s) => s
            .split(',')
            .filter_map(|p| {
                let v = u16::from_str_radix(p.trim(), 16).ok()?;
                Some([(v >> 8) as u8, v as u8])
            })
            .collect(),
        None => vec![
            TLS_ECDHE_SM4_GCM_SM3,
            TLS_ECDHE_SM4_CBC_SM3,
            TLS_ECC_SM4_GCM_SM3,
            TLS_ECC_SM4_CBC_SM3,
        ],
    };
    eprintln!("[client] offering suites: {:02X?}", offered);

    // No `with_gmssl_padding_compat(...)` call: the wire format always
    // follows RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3, which is what
    // current GmSSL master also follows.
    let connector = TlcpConnector::new()
        .with_server_sign_key(sign_pub, DEFAULT_DISTID.to_string())
        .with_cipher_suites(offered.clone());

    match connector.connect_with_certs(tcp).await {
        Ok(mut client) => {
            eprintln!("[client] handshake OK! suite = {:?}", client.cipher_suite());
            client
                .write_application_data(b"GET / HTTP/1.0\r\n\r\n")
                .await?;
            let resp = client.read_application_data().await?;
            eprintln!("[client] got {} bytes back", resp.len());
        }
        Err(e) => eprintln!("[client] handshake FAILED: {:?}", e),
    }
    Ok(())
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err("odd length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())?);
    }
    Ok(out)
}
