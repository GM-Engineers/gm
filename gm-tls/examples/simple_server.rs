//! Simple GM/TLS Server Example
//!
//! Running this example requires:
//! 1. Valid SM2 certificate and private key (server.pem, server-key.pem)
//! 2. CA certificate (ca.pem)
//! 3. Optional client CA certificate (client_ca.pem) for mutual authentication

use gm_tls::{TlsAcceptor, TlsConfig};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load configuration
    let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
        .with_alpn(vec!["http/1.1".to_string()])
        .with_require_client_auth(false); // Set to true to enable mutual authentication

    println!("TLS configuration loaded successfully");
    println!("  Require client authentication: false (set to true for mutual auth)");
    println!("  ALPN: http/1.1");

    // Create acceptor
    let acceptor = TlsAcceptor::new(config)?;
    println!("TLS acceptor created successfully");

    // Bind and listen
    let addr = "0.0.0.0:8443";
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Listening on {}", addr);

    loop {
        // Accept connection
        let (tcp, client_addr) = listener.accept().await?;
        println!("\nReceived connection from {}", client_addr);

        // Clone acceptor to move into spawn
        let acceptor = acceptor.clone();

        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    println!("TLS handshake successful");

                    // Read request
                    match tls.read_application_data().await {
                        Ok(data) => {
                            println!("Received request: {} bytes", data.len());
                            if let Ok(text) = String::from_utf8(data.clone()) {
                                println!("Request content:\n{}", text);
                            }

                            // Send response
                            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello";
                            if let Err(e) = tls.write_application_data(response).await {
                                eprintln!("Failed to send response: {}", e);
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to read request: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("TLS handshake failed: {}", e);
                }
            }
        });
    }
}
