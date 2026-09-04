//! Simple TLCP Client Example
//!
//! Connects to a TLCP server, sends an HTTP/1.1 request, and prints the response.
//!
//! ## Prerequisites
//!
//! 1. A running TLCP server (use `cargo run --example simple_server`)
//! 2. (Optional) Expected server signing public key, for verifying
//!    `ServerKeyExchange` signature. If not configured, the signature is NOT
//!    verified (insecure — for testing only).
//!
//! ## Run
//!
//! ```bash
//! # Start the server first
//! cargo run --example simple_server
//!
//! # Then in another terminal
//! cargo run --example simple_client
//! ```
//!
//! ## What this does
//!
//! 1. Constructs a `TlcpConnector` with all 4 TLCP cipher suites
//! 2. Opens a TCP connection to `127.0.0.1:8443`
//! 3. Performs the TLCP handshake (11 messages)
//! 4. Sends an HTTP/1.1 GET request over the encrypted channel
//! 5. Reads the server's echo response
//! 6. Closes the connection cleanly

use gm_tlcp::TlcpConnector;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Construct a TLCP connector with default settings
    //    (offers all 4 cipher suites, no session cache sharing)
    let connector = TlcpConnector::new();

    println!("TLCP client configuration loaded");
    println!("  Cipher suites: all 4 TLCP suites");
    println!("  Server signing key verification: disabled (testing only)");

    // 2. Open TCP connection
    let addr = "127.0.0.1:8443";
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    println!("TCP connection established to {}", addr);

    // 3. Perform TLCP handshake over the TCP stream
    let mut tls = connector.connect_with_certs(tcp).await?;
    println!("TLCP handshake completed");
    println!("  Protocol version: 0x0101 (TLCP)");
    println!(
        "  Role: {}",
        if tls.is_client() { "client" } else { "server" }
    );
    println!("  Session ID: {} bytes", tls.session_id().len());

    // 4. Send application data (HTTP request)
    let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    tls.write_application_data(request).await?;
    println!("Sent request: {} bytes", request.len());

    // 5. Read echo response
    let response = tls.read_application_data().await?;
    println!("Received response: {} bytes", response.len());
    println!("Response body:\n{}", String::from_utf8_lossy(&response));

    // 6. Graceful shutdown (sends TLCP close_notify alert)
    tls.close().await?;
    println!("Connection closed cleanly");

    Ok(())
}
