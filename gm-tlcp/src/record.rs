//! TLCP record layer helpers
//!
//! Minimal subset of gm-tls's record_layer needed by the TLCP stream
//! (currently just `next_nonce`). The full record layer (encryption,
//! decryption, framing) lives within `tlcp.rs` itself to keep the protocol
//! self-contained.

use gm_crypto::sm4::SM4_GCM_NONCE_LENGTH;

use crate::error::TlcpError;

/// Compute the next GCM nonce by XOR-ing the sequence number into the last
/// 8 bytes of the base nonce.
///
/// This is the same logic as `gm_tls::record_layer::next_nonce`, copied
/// during the gm-tls → gm-tlcp crate split to avoid pulling in gm-tls's
/// record layer for a single helper.
///
/// # Errors
/// Returns `TlcpError::SequenceOverflow` if `seq == u64::MAX` or if the
/// resulting nonce would collide with the base (nonce reuse check).
pub fn next_nonce(
    base: &[u8; SM4_GCM_NONCE_LENGTH],
    seq: u64,
) -> Result<[u8; SM4_GCM_NONCE_LENGTH], TlcpError> {
    if seq == u64::MAX {
        return Err(TlcpError::SequenceOverflow);
    }
    let mut nonce = *base;
    let ctr_bytes = seq.to_be_bytes();
    let n = ctr_bytes.len();
    // XOR the sequence number into the last 8 bytes of the nonce (RFC 8446 §5.3)
    for i in 0..n {
        nonce[SM4_GCM_NONCE_LENGTH - n + i] ^= ctr_bytes[i];
    }
    // Runtime safety check: GCM catastrophic failure on nonce reuse.
    // Each sequence number must produce a unique nonce; zero seq is
    // safe because it XORs 0 with the base (nonce == base for first use).
    if seq != 0 && nonce == *base {
        return Err(TlcpError::SequenceOverflow);
    }
    Ok(nonce)
}
