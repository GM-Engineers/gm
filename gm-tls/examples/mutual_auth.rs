//! Mutual Authentication (mTLS) Example
//!
//! This example demonstrates how to configure and use mutual authentication:
//! - Server requires client to present a valid certificate
//! - Both parties perform certificate verification

use gm_tls::{TlsAcceptor, TlsConfig, TlsConnector};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("=== GM/TLS Mutual Authentication Example ===\n");

    // Run server and client examples
    println!("Starting server...");
    tokio::spawn(async {
        if let Err(e) = run_server().await {
            eprintln!("Server error: {}", e);
        }
    });

    // Wait for server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    println!("\nStarting client...");
    if let Err(e) = run_client().await {
        eprintln!("Client error: {}", e);
    }

    println!("\n=== Example completed ===");
    Ok(())
}

/// Run the server
async fn run_server() -> Result<(), Box<dyn Error>> {
    // Configuration: require client certificate
    let config = TlsConfig::load("server.pem", "server-key.pem", "ca.pem")?
        .with_require_client_auth(true) // Enable mutual authentication
        .with_alpn(vec!["http/1.1".to_string()]);

    let acceptor = TlsAcceptor::new(config)?;
    println!("Server: TLS acceptor created successfully");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8444").await?;
    println!("Server: listening on 127.0.0.1:8444");

    let (tcp, addr) = listener.accept().await?;
    println!("Server: received connection from {}", addr);

    // Use accept_with_client_cert to get client certificate info
    let (mut tls, client_cert_pem, _session_ticket) = acceptor.accept_with_client_cert(tcp).await?;
    println!("Server: TLS handshake completed");

    // Display client certificate info
    if let Some(cert_pem) = &client_cert_pem {
        println!(
            "Server: received client certificate PEM ({} bytes)",
            cert_pem.len()
        );
        // In production, you would parse the certificate for further verification
    } else {
        println!("Server: no client certificate received");
    }

    // Read client data
    let data = tls.read_application_data().await?;
    println!("Server: received data ({} bytes)", data.len());

    // Send response
    let response = b"Hello from server - mTLS connected!";
    tls.write_application_data(response).await?;
    println!("Server: sent response");

    Ok(())
}

/// Run the client
async fn run_client() -> Result<(), Box<dyn Error>> {
    // Configuration: provide client certificate
    let config = TlsConfig::load("client.pem", "client-key.pem", "ca.pem")?
        .with_domain("localhost".to_string())
        .with_alpn(vec!["http/1.1".to_string()]);

    let connector = TlsConnector::new(config)?;
    println!("Client: TLS connector created successfully");

    let tcp = tokio::net::TcpStream::connect("127.0.0.1:8444").await?;
    println!("Client: TCP connection established");

    let mut tls = connector.connect(tcp).await?;
    println!("Client: TLS handshake completed");

    // Send data
    let message = b"Hello from client - requesting secure connection";
    tls.write_application_data(message).await?;
    println!("Client: sent data ({} bytes)", message.len());

    // Receive response
    let response = tls.read_application_data().await?;
    println!("Client: received response ({} bytes)", response.len());

    if let Ok(text) = String::from_utf8(response) {
        println!("Client: response content: {}", text);
    }

    Ok(())
}
