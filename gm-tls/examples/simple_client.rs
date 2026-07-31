//! Simple GM/TLS Client Example
//!
//! Running this example requires:
//! 1. Valid SM2 certificate and private key (client.pem, client-key.pem)
//! 2. CA certificate (ca.pem)
//! 3. A running GM/TLS server
//!
//! Generate test certificates:
//! ```bash
//! # Use gm-ca or other CA tool to generate
//! openssl req -newkey sm2 -pkeyopt ec_paramgen_curve:sm2 -out client.csr
//! openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -out client.pem
//! ```

use gm_tls::{TlsConfig, TlsConnector};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Load configuration (replace with actual certificate paths in production)
    let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
        .with_domain("example.com".to_string())
        .with_alpn(vec!["http/1.1".to_string()]);

    println!("TLS configuration loaded successfully");
    println!("  Domain: example.com");
    println!("  ALPN: http/1.1");

    // Create connector
    let connector = TlsConnector::new(config)?;
    println!("TLS connector created successfully");

    // Connect to server
    let addr = "127.0.0.1:8443";
    println!("Connecting to {}", addr);

    let tcp = tokio::net::TcpStream::connect(addr).await?;
    println!("TCP connection established");

    let mut tls = connector.connect(tcp).await?;
    println!("TLS handshake completed");

    // Send request
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    tls.write_application_data(request).await?;
    println!("Request sent: {} bytes", request.len());

    // Read response
    let response = tls.read_application_data().await?;
    println!("Response received: {} bytes", response.len());

    if let Ok(text) = String::from_utf8(response.clone()) {
        println!("Response content:\n{}", text);
    }

    println!("Communication completed");
    Ok(())
}
