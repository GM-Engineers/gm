//! Regression tests verifying that `GmTlsStream::AsyncRead::poll_read`
//! resumes correctly across short reads followed by `Poll::Pending`.
//! Without persistent partial-read state, every `poll_read` is a fresh
//! synchronous frame and bytes already pulled off the wire would be
//! dropped on the next poll, desynchronising the record stream.

use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;
use gm_tls::gm::SessionKeys;
use gm_tls::record_layer::GmTlsStream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};

/// Wraps an `AsyncRead` so each successful `poll_read` yields at most one
/// byte. Paired with a small ring buffer this forces `Pending` between
/// bytes, exercising the partial-read path.
struct OneBytePerPoll<R: AsyncRead> {
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for OneBytePerPoll<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Cap the caller's effective read at 1 byte by handing the inner
        // stream a 1-byte scratch buffer and forwarding what it filled.
        let mut one = [0u8; 1];
        let mut scratch = ReadBuf::new(&mut one[..]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut scratch) {
            Poll::Ready(Ok(())) => {
                let n = scratch.filled().len();
                if n > 0 {
                    if buf.remaining() < n {
                        return Poll::Ready(Err(std::io::Error::other(
                            "downstream buffer too small for one byte",
                        )));
                    }
                    buf.put_slice(&one[..n]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// `GmTlsStream::new` requires its stream parameter to be `AsyncRead +
// AsyncWrite + Unpin`.
impl<R: AsyncWrite + AsyncRead + Unpin> AsyncWrite for OneBytePerPoll<R> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn shared_keys() -> SessionKeys {
    SessionKeys {
        client_key: vec![0x11u8; 16],
        client_nonce: [0x22u8; SM4_GCM_NONCE_LENGTH],
        server_key: vec![0x33u8; 16],
        server_nonce: [0x44u8; SM4_GCM_NONCE_LENGTH],
    }
}

/// Verifies that a `GmTlsStream` reader whose underlying transport
/// delivers one byte per poll still reconstructs a multi-byte record
/// across short reads and `Pending` returns.
#[tokio::test(flavor = "current_thread")]
async fn poll_read_resumes_after_one_byte_reads() {
    // The writer and reader must run as separate tasks so back-pressure on
    // the 1-byte ring buffer does not deadlock the test runtime.
    let (client_io, server_io) = duplex(1);

    let keys = shared_keys();

    let writer_keys = keys.clone();
    let reader_keys = keys;

    let writer_task = tokio::spawn(async move {
        let mut writer = GmTlsStream::new(client_io, writer_keys, true, None, None);
        writer
            .write_application_data(b"hello world")
            .await
            .expect("writer should encrypt plaintext");
        writer.flush().await.expect("flush should succeed");
        // Dropping the writer closes the client-side of the duplex,
        // which delivers the remaining 1 byte plus EOF to the reader.
        drop(writer);
    });

    let reader_task = tokio::spawn(async move {
        let limited = OneBytePerPoll { inner: server_io };
        let mut reader = GmTlsStream::new(limited, reader_keys, false, None, None);
        let mut out = vec![0u8; b"hello world".len()];
        reader
            .read_exact(&mut out)
            .await
            .expect("reader should decrypt across one-byte chunked reads");
        out
    });

    let (_, plaintext) = tokio::join!(writer_task, reader_task);
    let plaintext = plaintext.expect("reader task panicked");
    assert_eq!(&plaintext, b"hello world");
}

/// Verifies that a second record also resumes correctly after the
/// first. Guards against the partial-read state being skipped on
/// records after the first.
#[tokio::test(flavor = "current_thread")]
async fn poll_read_resumes_across_two_records() {
    let (client_io, server_io) = duplex(1);
    let keys = shared_keys();

    let writer_keys = keys.clone();
    let reader_keys = keys;

    let writer_task = tokio::spawn(async move {
        let mut writer = GmTlsStream::new(client_io, writer_keys, true, None, None);
        writer
            .write_application_data(b"first message")
            .await
            .expect("first write");
        writer
            .write_application_data(b"second message")
            .await
            .expect("second write");
        writer.flush().await.expect("flush");
        drop(writer);
    });

    let reader_task = tokio::spawn(async move {
        let limited = OneBytePerPoll { inner: server_io };
        let mut reader = GmTlsStream::new(limited, reader_keys, false, None, None);
        let mut first = vec![0u8; b"first message".len()];
        reader
            .read_exact(&mut first)
            .await
            .expect("first read should succeed");
        let mut second = vec![0u8; b"second message".len()];
        reader
            .read_exact(&mut second)
            .await
            .expect("second read should succeed");
        (first, second)
    });

    let (_, reader_join) = tokio::join!(writer_task, reader_task);
    let (first, second) = reader_join.expect("reader task panicked");
    assert_eq!(&first, b"first message");
    assert_eq!(&second, b"second message");
}
