//! TCP proxy that logs every byte in hex for debugging TLCP interop.
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let proxy_port: u16 = args[1].parse()?;
    let upstream_host = args[2].clone();
    let upstream_port: u16 = args[3].parse()?;

    let listener = TcpListener::bind(("127.0.0.1", proxy_port)).await?;
    eprintln!(
        "[proxy] listening on 127.0.0.1:{} -> {}:{}",
        proxy_port, upstream_host, upstream_port
    );

    loop {
        let (client, peer) = listener.accept().await?;
        let peer_str = peer.to_string();
        eprintln!(
            "[proxy] client {} connected; dialing {}:{}",
            peer_str, upstream_host, upstream_port
        );
        let upstream = match TcpStream::connect((upstream_host.as_str(), upstream_port)).await {
            Ok(u) => {
                eprintln!(
                    "[proxy] upstream {}:{} connected",
                    upstream_host, upstream_port
                );
                u
            }
            Err(e) => {
                eprintln!(
                    "[proxy] upstream connect FAILED for {}: {}; closing client",
                    peer_str, e
                );
                drop(client);
                continue;
            }
        };
        let (cr, cw) = client.into_split();
        let (ur, uw) = upstream.into_split();
        let id1 = peer_str.clone();
        let id2 = peer_str.clone();
        tokio::spawn(async move {
            let _ = pipe("C->S", cr, uw, id1).await;
        });
        tokio::spawn(async move {
            let _ = pipe("S->C", ur, cw, id2).await;
        });
    }
}

async fn pipe<R, W>(
    label: &'static str,
    mut reader: R,
    mut writer: W,
    peer: String,
) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 16384];
    let mut total = 0;
    loop {
        let n = match tokio::time::timeout(Duration::from_secs(10), reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            _ => break,
        };
        total += n;
        eprintln!(
            "[proxy] {} ({}) {} bytes (total={}): {}",
            label,
            peer,
            n,
            total,
            hex::encode(&buf[..n.min(120)])
        );
        if writer.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    Ok(())
}
