//! Simple TLCP Server Example
//!
//! Echoes back any application data received from TLCP clients.
//!
//! ## Prerequisites
//!
//! 1. SM2 **signing** certificate (DER format): `server-sign.crt`
//! 2. SM2 **encryption** certificate (DER format): `server-enc.crt`
//! 3. SM2 signing key (PEM format): `server-sign.key.pem`
//! 4. SM2 encryption key (PEM format): `server-enc.key.pem`
//!
//! TLCP requires **dual certificates** (one for signing, one for encryption),
//! unlike TLS 1.3 which uses a single certificate.
//!
//! ## Generate test certificates
//!
//! ```bash
//! # Using gm-ca or openssl with SM2
//! # (See gm-ca docs for SM2 cert generation)
//! ```
//!
//! ## Run
//!
//! ```bash
//! cargo run --example simple_server
//! ```
//!
//! Then in another terminal:
//!
//! ```bash
//! cargo run --example simple_client
//! ```

use gm_tlcp::{TlcpAcceptor, TlcpError};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Load dual certificates (DER-encoded X.509)
    let sign_cert = std::fs::read("server-sign.crt")?;
    let enc_cert = std::fs::read("server-enc.crt")?;

    // 2. Load dual private keys (PEM-encoded SM2)
    let sign_pem = std::fs::read_to_string("server-sign.key.pem")?;
    let enc_pem = std::fs::read_to_string("server-enc.key.pem")?;
    let sign_key = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&sign_pem)?;
    let enc_key = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(&enc_pem)?;

    // 3. Construct Acceptor with dual certificates
    let acceptor = TlcpAcceptor::new().with_dual_certs(sign_cert, enc_cert, sign_key, enc_key);

    println!("TLCP server configuration loaded");
    println!("  Cipher suites: all 4 TLCP suites (ECDHE/GCM, ECDHE/CBC, ECC/GCM, ECC/CBC)");
    println!("  Version: 0x0101 (TLCP)");

    // 4. Bind and listen for TLCP clients
    let addr = "0.0.0.0:8443";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Listening on {} (TLCP)", addr);

    loop {
        let (tcp, peer_addr) = listener.accept().await?;
        println!("\n[+] New TCP connection from {}", peer_addr);

        // Clone acceptor to move into the spawned task
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            // Perform TLCP handshake (11 messages: ClientHello → ... → Finished)
            let mut tls = match acceptor.accept_with_certs(tcp).await {
                Ok(s) => {
                    println!("[{}] TLCP handshake successful", peer_addr);
                    s
                }
                Err(e) => {
                    eprintln!("[{}] TLCP handshake failed: {}", peer_addr, e);
                    return Err::<(), TlcpError>(e);
                }
            };

            // Echo loop: read request, write response.
            // Note: An empty Vec (data.is_empty()) is NOT an EOF signal here —
            // it means the peer sent a zero-length APP_DATA record (unusual).
            // True EOF surfaces as a TlcpError::IoError on the read path.
            loop {
                match tls.read_application_data().await {
                    Ok(data) if data.is_empty() => {
                        println!("[{}] Received zero-length APP_DATA record; ending echo loop", peer_addr);
                        break;
                    }
                    Ok(data) => {
                        println!(
                            "[{}] Received {} bytes: {:?}",
                            peer_addr,
                            data.len(),
                            String::from_utf8_lossy(&data)
                        );

                        // Echo back
                        if let Err(e) = tls.write_application_data(&data).await {
                            eprintln!("[{}] Write failed: {}", peer_addr, e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[{}] Read failed: {}", peer_addr, e);
                        break;
                    }
                }
            }
            Ok::<(), TlcpError>(())
        });
    }
}
