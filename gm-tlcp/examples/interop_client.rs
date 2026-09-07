//! Standalone TLCP client for interop testing.
//!
//! Usage: interop_client PORT  SIGN_PUB_HEX  [SUITES_HEX_CSV]  [COMPAT]
//!        [CLIENT_SIGN_DER CLIENT_ENC_DER CLIENT_SIGN_KEY PEM CLIENT_ENC_KEY PEM]
//!
//! - PORT: TCP port of the TLCP server.
//! - SIGN_PUB_HEX: 130-character hex of the server's uncompressed SM2
//!   sign public key (65 bytes; leading 0x04).
//! - SUITES_HEX_CSV: optional comma-separated list of cipher suite IDs
//!   in hex (e.g. "e013,e003"). Defaults to all four TLCP suites.
//! - COMPAT: deprecated, kept for CLI compatibility. The wire format
//!   always follows RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.
//! - CLIENT_SIGN_DER / CLIENT_ENC_DER / CLIENT_SIGN_KEY PEM /
//!   CLIENT_ENC_KEY PEM: optional paths for mutual-auth ECDHE
//!   handshakes against servers that send `CertificateRequest`. The
//!   certs are read as DER, the keys as PKCS#8 PEM. For TLCP ECDHE,
//!   peers expect BOTH sign + enc certs; both are sent (sign first,
//!   enc second) per GB/T 38636-2020 §6.4.6. All four paths must be
//!   supplied together (or none of them).
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

    // Optional client cert (mutual-auth ECDHE only; static-ECC suites
    // do not request a client cert per TLCP). Path-style is positional;
    // all four (sign DER, enc DER, sign key PEM, enc key PEM) must be
    // present or none of them.
    let client_sign_der = args.get(5).cloned();
    let client_enc_der = args.get(6).cloned();
    let client_sign_key_pem_path = args.get(7).cloned();
    let client_enc_key_pem_path = args.get(8).cloned();
    let has_client_certs = matches!(
        (
            client_sign_der.as_ref(),
            client_enc_der.as_ref(),
            client_sign_key_pem_path.as_ref(),
            client_enc_key_pem_path.as_ref()
        ),
        (Some(_), Some(_), Some(_), Some(_))
    );

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
    let mut connector = TlcpConnector::new()
        .with_server_sign_key(sign_pub, DEFAULT_DISTID.to_string())
        .with_cipher_suites(offered.clone());

    if has_client_certs {
        let sign_der_path = client_sign_der.expect("checked above");
        let enc_der_path = client_enc_der.expect("checked above");
        let sign_key_path = client_sign_key_pem_path.expect("checked above");
        let enc_key_path = client_enc_key_pem_path.expect("checked above");
        let sign_der = std::fs::read(&sign_der_path)
            .map_err(|e| format!("read client sign cert DER {}: {}", sign_der_path, e))?;
        let enc_der = std::fs::read(&enc_der_path)
            .map_err(|e| format!("read client enc cert DER {}: {}", enc_der_path, e))?;
        let sign_key_pem = std::fs::read_to_string(&sign_key_path)
            .map_err(|e| format!("read client sign key PEM {}: {}", sign_key_path, e))?;
        let enc_key_pem = std::fs::read_to_string(&enc_key_path)
            .map_err(|e| format!("read client enc key PEM {}: {}", enc_key_path, e))?;
        eprintln!(
            "[client] client certs: sign {}B, enc {}B; sign+enc keys loaded",
            sign_der.len(),
            enc_der.len()
        );
        // TLCP GB/T 38636-2020 §6.4.6: client sends sign cert first,
        // then enc cert. openHiTLS' server reads the enc cert off the
        // second entry of the chain and rejects the handshake with
        // HITLS_CERT_ERR_EXP_CERT if it is missing.
        connector = connector.with_client_certs(
            vec![sign_der, enc_der],
            sign_key_pem,
            Some(enc_key_pem),
            None,
        );
    }

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
