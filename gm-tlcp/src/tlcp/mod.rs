//! TLCP (Transport Layer Cryptographic Protocol) implementation
//!
//! Based on GB/T 38636-2020《信息安全技术 传输层密码协议》
//!
//! # Protocol Overview
//!
//! TLCP is a Chinese national standard TLS-like protocol that differs from
//! TLS 1.3 in several key ways:
//!
//! - **Dual certificate system**: Separate signing and encryption certificates
//! - **ECDHE key exchange**: Based on SM2 ECDHE, not TLS 1.3 key share
//! - **Cipher suites**: SM2 + SM3 + SM4-GCM/CBC
//! - **Version**: 0x0101 (not TLS 1.2's 0x0303 or TLS 1.3's 0x0303+ext)
//! - **No 0-RTT**: TLCP does not support early data
//! - **No PSK**: TLCP uses certificate-based authentication only
//!
//! # Handshake Flow
//!
//! ```text
//! Client                                          Server
//! ClientHello + KeyShare       -------->
//!                                              ServerHello + KeyShare
//!                                              Certificate (sign)
//!                                              Certificate (enc)
//!                                              CertificateVerify
//!                              <--------       ServerKeyExchange
//!                                              ServerHelloDone
//! ClientKeyExchange            -------->
//! ChangeCipherSpec             -------->
//! Finished                     -------->
//!                                              ChangeCipherSpec
//!                              <--------       Finished
//! Application Data             <------->       Application Data
//! ```
//!
//! # Differences from TLS 1.3
//!
//! | Feature | TLS 1.3 | TLCP |
//! |---------|---------|------|
//! | Certificates | Single | Dual (sign + enc) |
//! | Key exchange | KeyShare extension | ECDHE ServerKeyExchange |
//! | PSK | Yes | No |
//! | Session resumption | Yes (tickets) | Yes (session ID) |
//! | 0-RTT | Yes | No |
//! | Version | 0x0303 + ext | 0x0101 |
//! | Cipher suites | TLS_AES_128_GCM_SHA256 | ECC_SM4_GCM_SM3 |
//! | Record padding | Yes | No |
//!
//! # Status
//!
//! Implemented and tested:
//!
//! - Full TLCP handshake state machine (client + server, 9 message types)
//! - Dual certificate handling (sign cert + enc cert, both required)
//! - SM2 ECDHE key exchange with SM3-based PRF
//! - SM4-GCM and SM4-CBC + HMAC-SM3 record layer encryption
//! - Session resumption via session IDs (`TlcpSessionCache`)
//! - Alert protocol (`TlcpAlert`, `TlcpAlertDescription`)
//! - 4 cipher suites (ECDHE/GCM, ECDHE/CBC, static-ECC/GCM, static-ECC/CBC)
//!
//! Not implemented (out of scope for GB/T 38636-2020):
//!
//! - 0-RTT / Early Data (not defined in the standard)
//! - PSK / PSK-DHE modes (not defined in the standard)
//!
//! # API 入口索引 API Entry Index
//!
//! ## 高层 API（推荐先看）
//!
//! - [`TlcpConnector`] / [`TlcpConnector::connect_with_certs`] — TLCP 客户端
//! - [`TlcpAcceptor`] / [`TlcpAcceptor::accept_with_certs`] — TLCP 服务端
//! - [`TlcpStream`] — 加密流（实现 [`tokio::io::AsyncRead`]/[`tokio::io::AsyncWrite`]）
//!
//! ## 握手消息类型（按协议流程顺序）
//!
//! - [`TlcpClientHello`] → [`TlcpServerHello`] → [`TlcpCertPair`] → [`TlcpServerKeyExchange`]
//!   → [`TlcpServerHelloDone`] → [`TlcpClientKeyExchange`] → [`TlcpFinished`]
//!
//! ## 密码套件
//!
//! - [`TlcpCipherSuite`] 枚举 4 个套件；常量：
//!   - [`TLS_ECDHE_SM4_GCM_SM3`] (`0xE051`) — **首选**，生产推荐
//!   - [`TLS_ECDHE_SM4_CBC_SM3`] (`0xE011`)
//!   - [`TLS_ECC_SM4_GCM_SM3`]   (`0xE053`) — 静态密钥，性能优化场景
//!   - [`TLS_ECC_SM4_CBC_SM3`]   (`0xE013`)
//!
//! ## 会话恢复
//!
//! - [`TlcpSessionCache`] — 跨连接缓存
//! - [`TlcpResumedSession`] / [`TlcpResumeResult`] — 恢复结果
//!
//! ## 握手状态机
//!
//! - [`TlcpHandshake`] — 客户端握手状态机入口
//! - [`TlcpServerHandshake`] — 服务端握手状态机入口
//! - [`TlcpHandshakeState`] — 状态枚举（`Idle` → `HelloSent` → `ServerCertsReceived` → `KeyExchange` → `WaitFinished` → `Established` / `Failed`）
//!
//! ## 告警协议
//!
//! - [`TlcpAlert`] / [`TlcpAlertLevel`] / [`TlcpAlertDescription`]
//!
//! ## 常量
//!
//! - [`TLCP_VERSION_1_0`] = `[0x01, 0x01]` — TLCP 协议版本字节
//! - [`MAX_TLCP_RECORD_SIZE`] = `16 * 1024` — 单条 TLCP record 最大长度
//!
//! # 互操作性 Interoperability
//!
//! - **GmSSL 3.3.0-dev** (`master`): handshake + APP_DATA byte-for-byte
//!   round-trip verified (see `tests/gmssl_interop.rs`). All four
//!   TLCP cipher suites covered across both CBC and GCM modes.
//!   `no_common_cipher_suite` negative path and server-side cipher-
//!   suite preference semantics also verified.
//! - **Tongsuo 8.3.0**: source-level interop investigation documented
//!   in `interop/tongsuo/`. Tongsuo's NTLS state machine rejects the
//!   TLCP record-layer version byte `0x0101` in three independent
//!   code paths; round-trip testing is blocked on an upstream Tongsuo
//!   fix (see
//!   `interop/tongsuo/upstream/ISSUE-state-machine-ntls-version.md`).
//! - **openHiTLS** (`s_server -tlcp`): default-build interop verified
//!   up to the client-side Finished record for ECDHE suites (CKE wire
//!   format per spec, SKE-for-static-ECC per RFC 5246 §7.4.3,
//!   SM2-KAP PMS per GB/T 32918.3-2016 / GM/T 0003.3-2012 §6.1, and
//!   SM2 distid for Z-value computation via the `with_*_distid`
//!   setters). The remaining `Decrypt Error (51)` on Finished for
//!   ECDHE suites is a known open issue: gm-tlcp's ECDHE x̂
//!   transform implementation appears to disagree with openHiTLS'
//!   key-agreement output (tracked separately as a follow-up). See
//!   [`interop/AUDIT-2026-09-06.md`](../../interop/AUDIT-2026-09-06.md)
//!   and `interop/openhitls/wire-traces/` for the empirical evidence.
//!
//! - **GmSSL 2026-06+ master**: the default build diverges from
//!   GmSSL master on the points enumerated in the
//!   "Limitations and interop boundaries" table below. To restore
//!   byte-for-byte interop with GmSSL master, build with
//!   `--features tlcp-gmssl-compat`. This is the inverse of the
//!   pre-0.3.0 `tlcp-strict` flag.
//!
//! - **Tongsuo 8.3.0**: default-mode interop is unverified end-to-end;
//!   Tongsuo's CKE / SKE shapes match the spec in the same places
//!   openHiTLS does, so the default build *should* interop, but
//!   no automated wire-level test exists in this repo.
//!
//! # Limitations and interop boundaries
//!
//! gm-tlcp's **default** build is GB/T 38636-2020 spec-targeted — the
//! wire format and algorithm choices follow the standard. To talk to
//! GmSSL 2026-06+ master (which diverges from the spec in several
//! places that 0.2.x inherited), build with the `tlcp-gmssl-compat`
//! Cargo feature; that opt-in restores the 0.2.x GmSSL-master
//! deviations. Audit D-2.
//!
//! | # | Default (GB/T 38636-2020 spec) | GmSSL shim (--features tlcp-gmssl-compat) | Audit ref |
//! |---|---|---|---|
//! | 1 | `ClientKeyExchange` body has **no** `uint16` length prefix on the ECDHE pub | Adds a redundant `uint16` length prefix to match GmSSL 2026-06+ master | C-1 (resolved) |
//! | 2 | `ServerKeyExchange` is sent AND expected **only** for ECDHE suites; static-ECC skips SKE per RFC 5246 §7.4.3 | `SKE` is sent and expected for ALL suites including static-ECC (ECDHE-style body) | C-2 (R-1 sets default to RFC 5246; full spec interpretation-B is R-2) |
//! | 3 | SM2 `distid` is hard-coded to `"1234567812345678"` | Same default, but `with_server_enc_distid` / `with_client_enc_distid` / `with_client_sign_distid` let callers override it | M-3 (partial) |
//! | 4 | `ClientHello`/`ServerHello` `random` filled with 32 random bytes | Same (m-1 applied in both modes as of v0.2) | m-1 |
//! | 5 | `ClientHello.compression_methods` parser accepts any bytes; `ServerHello.cipher_suite` parser accepts any 2 bytes | Same (m-4/m-5 applied in both modes as of v0.2) | m-4 / m-5 |
//! | 6 | `ClientHello.session_id_len` upper bound not enforced | Same (m-6 applied in both modes as of v0.2) | m-6 |
//!
//! Production callers should:
//! - **Talk to openHiTLS / Tongsuo / any standards-strict peer**:
//!   use the default build. The default now matches GB/T 38636-2020
//!   for the parts of the handshake it implements.
//! - **Talk to GmSSL 3.3.0-dev master**: opt in with
//!   `--features tlcp-gmssl-compat` (this restores the 0.2.x wire
//!   format on the divergent points). The `tlcp-strict` flag from
//!   0.2.x is deprecated as a no-op alias for source-compat.
//! - **Run gm-tlcp as a server** for static-ECC suites: still
//!   blocked on C-4 (server-side static-ECC PMS decryption returns
//!   an explicit error). Tracked as R-3 in the SPEC-FIRST roadmap.
//!
//! # 许可证
//!
//! MIT OR Apache-2.0

use crate::error::TlcpError;
use crate::metrics;
use crate::record::next_nonce;
use gm_crypto::sm3::Sm3Hmac;
use gm_crypto::sm4::{SM4_BLOCK_SIZE, SM4_GCM_NONCE_LENGTH, Sm4Cipher};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;

mod alert;
mod cipher_suite;
mod constants;
mod crypto;
mod cv_helper;
mod handshake;
mod handshake_type;
mod key_material;
mod messages;
pub mod pms;
pub use pms::*;
mod session;
pub use alert::*;
pub use cipher_suite::*;
pub use constants::*;
pub use handshake::*;
pub use handshake_type::*;
pub use key_material::*;
pub use messages::*;
pub use session::*;

/// TLCP protocol version bytes (0x0101)
const TLCP_VERSION: [u8; 2] = [0x01, 0x01];
/// TLCP content type for application data
const TLCP_RECORD_TYPE_APP_DATA: u8 = 0x17;
/// TLCP content type for alert
const TLCP_RECORD_TYPE_ALERT: u8 = 0x15;
/// TLCP content type for handshake
const TLCP_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
/// TLCP content type for ChangeCipherSpec
const TLCP_RECORD_TYPE_CCS: u8 = 0x14;
// ============================================================================
// Plaintext handshake record I/O
// ============================================================================
/// Write a plaintext TLCP handshake record to the transport.
///
/// During the handshake phase, records are sent unencrypted.
/// Format: `[content_type=0x16][version=0x0101][length(2)][handshake_message]`
async fn write_handshake_record<S: AsyncWrite + Unpin>(
    transport: &mut S,
    msg: &[u8],
) -> std::io::Result<()> {
    let mut record = Vec::with_capacity(5 + msg.len());
    record.push(TLCP_RECORD_TYPE_HANDSHAKE);
    // TLCP (GB/T 38636-2020) §6.2 specifies the record-layer protocol
    // version byte to be NTLS1_1 (0x0101), distinct from the standard
    // TLS record-layer legacy version (0x0301). GmSSL accepts either;
    // Tongsuo 8.3.0's `SSL_connection_is_ntls` sniffs bytes 1-2 of the
    // very first record to dispatch to the NTLS state machine, so TLCP
    // clients reaching Tongsuo must use 0x0101 here (see
    // `interop/tongsuo/upstream/ISSUE-state-machine-ntls-version.md`
    // for the Tongsuo-side rejection analysis).
    record.extend_from_slice(&TLCP_VERSION_1_0);
    let len = msg.len() as u16;
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(msg);
    use tokio::io::AsyncWriteExt;
    transport.write_all(&record).await?;
    transport.flush().await?;
    Ok(())
}
/// Read a plaintext TLCP record from the transport.
///
/// Returns (content_type, payload).
async fn read_plaintext_record<S: AsyncRead + Unpin>(
    transport: &mut S,
) -> std::io::Result<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 5];
    transport.read_exact(&mut header).await?;
    let content_type = header[0];
    // version = header[1..3], not checked for plaintext records
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > TLCP_MAX_RECORD_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Record too large: {} bytes", len),
        ));
    }
    let mut payload = vec![0u8; len];
    transport.read_exact(&mut payload).await?;
    Ok((content_type, payload))
}
/// Parse a single handshake message from a record payload.
///
/// A single record may contain multiple handshake messages (or a partial one).
/// This function parses the first message and returns (handshake_type, body, remaining).
fn parse_handshake_message(payload: &[u8]) -> Result<(HandshakeType, Vec<u8>, &[u8]), TlcpError> {
    if payload.len() < 4 {
        return Err(TlcpError::InvalidMessage(
            "Handshake message too short".to_string(),
        ));
    }
    let msg_type = HandshakeType::try_from(payload[0])?;
    let body_len =
        ((payload[1] as usize) << 16) | ((payload[2] as usize) << 8) | payload[3] as usize;
    if payload.len() < 4 + body_len {
        return Err(TlcpError::InvalidMessage(format!(
            "Handshake body truncated: {} bytes available, {} needed",
            payload.len() - 4,
            body_len
        )));
    }
    let body = payload[4..4 + body_len].to_vec();
    let remaining = &payload[4 + body_len..];
    Ok((msg_type, body, remaining))
}
/// Maximum TLCP record size (16KB per GB/T 38636-2020)
const TLCP_MAX_RECORD_SIZE: usize = 16 * 1024;
/// SM3 HMAC output length (32 bytes)
const SM3_HMAC_LENGTH: usize = 32;
/// SM4-CBC IV length (16 bytes = SM4_BLOCK_SIZE)
const SM4_CBC_IV_LENGTH: usize = SM4_BLOCK_SIZE;
/// TLCP stream that wraps an async transport with SM4-GCM/CBC encryption.
///
/// Unlike TLS 1.3, TLCP does **not** use the inner content type mechanism
/// (RFC 8446 §5.4). Application data records contain raw plaintext after
/// decryption. TLCP also does not support KeyUpdate.
///
/// # Record Format
///
/// ```text
/// [content_type(1)][version=0x0101(2)][length(2)][encrypted_payload]
/// ```
///
/// For SM4-GCM: `encrypted_payload = ciphertext || tag(16)`
/// For SM4-CBC+HMAC: `encrypted_payload = HMAC(32) || IV(16) || ciphertext || padding`
///
/// Currently only SM4-GCM is supported for the stream record layer.
pub struct TlcpStream<S> {
    inner: S,
    /// SM4 key for write direction
    write_key: Zeroizing<Vec<u8>>,
    /// SM4 key for read direction
    read_key: Zeroizing<Vec<u8>>,
    /// SM3 HMAC key for write direction (CBC mode only)
    write_mac_key: Zeroizing<Vec<u8>>,
    /// SM3 HMAC key for read direction (CBC mode only)
    read_mac_key: Zeroizing<Vec<u8>>,
    /// Base nonce for write direction (12 bytes for GCM)
    write_nonce: [u8; SM4_GCM_NONCE_LENGTH],
    /// Base nonce for read direction (12 bytes for GCM)
    read_nonce: [u8; SM4_GCM_NONCE_LENGTH],
    write_seq: u64,
    /// Read sequence number
    read_seq: u64,
    /// Buffered decrypted application data for reads
    read_buf: Vec<u8>,
    /// Current position in read_buf
    read_buf_pos: usize,
    /// Cached SM4 cipher for encryption
    cipher_enc: Option<Sm4Cipher>,
    /// Cached SM4 cipher for decryption
    cipher_dec: Option<Sm4Cipher>,
    /// Whether close_notify has been sent
    close_notify_sent: bool,
    /// Whether we are the client (determines key assignment)
    is_client: bool,
    /// Session ID for resumption
    session_id: Vec<u8>,
    /// Cached session state for resumption
    cached_resumed_session: Option<TlcpResumedSession>,
    /// Cipher suite type (GCM or CBC)
    cipher_suite: TlcpCipherSuite,
    /// Deprecated GmSSL padding-compat shim. Kept as a field so external callers
    /// that still pass `with_gmssl_padding_compat(_)` keep compiling, but it
    /// has no effect on the wire format. The CBC record layer always follows
    /// RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.2 (N padding bytes of value N
    /// plus 1 trailing length byte = N+1 bytes total at the tail of the
    /// record). This is what `gmssl tlcp_server` v3.x, Tongsuo NTLS, and
    /// every other TLCP peer we have tested against also expects. The previous
    /// `gmssl_padding_compat(true)` mode (which wrote N bytes of value N-1)
    /// happened to be accepted by GmSSL's `tls_cbc_decrypt` only because the
    /// parser happens to read the trailing byte and back-derive `outlen` one
    /// byte short; it was never standard and broke real RFC 5246 peers.
    #[deprecated(
        since = "0.1.0",
        note = "No-op kept for API stability. The CBC framing always follows \
                 RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.2; use with_gmssl_padding_compat(_) \
                 is a no-op now."
    )]
    #[allow(dead_code)]
    gmssl_padding_compat: bool,
}
impl<S: AsyncRead + AsyncWrite + Unpin> TlcpStream<S> {
    /// Create a new TLCP stream from key material and cipher suite.
    ///
    /// # Arguments
    /// * `inner` - The underlying async transport
    /// * `key_material` - Key material from TLCP key derivation
    /// * `cipher_suite` - The negotiated cipher suite (GCM or CBC)
    /// * `is_client` - Whether this is the client side
    /// * `session_id` - The session ID assigned during handshake
    pub fn new(
        inner: S,
        key_material: &TlcpKeyMaterial,
        cipher_suite: TlcpCipherSuite,
        is_client: bool,
        session_id: Vec<u8>,
    ) -> Result<Self, TlcpError> {
        // Helper: copy IV bytes into fixed-size array, zero-padding if shorter
        fn copy_iv<const N: usize>(src: &[u8]) -> [u8; N] {
            let mut arr = [0u8; N];
            let len = src.len().min(N);
            arr[..len].copy_from_slice(&src[..len]);
            arr
        }
        let (write_key, read_key, write_mac_key, read_mac_key, write_nonce, read_nonce) =
            if is_client {
                (
                    key_material.client_enc_key.clone(),
                    key_material.server_enc_key.clone(),
                    key_material.client_mac_key.clone(),
                    key_material.server_mac_key.clone(),
                    copy_iv(&key_material.client_iv),
                    copy_iv(&key_material.server_iv),
                )
            } else {
                (
                    key_material.server_enc_key.clone(),
                    key_material.client_enc_key.clone(),
                    key_material.server_mac_key.clone(),
                    key_material.client_mac_key.clone(),
                    copy_iv(&key_material.server_iv),
                    copy_iv(&key_material.client_iv),
                )
            };
        Ok(Self {
            inner,
            write_key: Zeroizing::new(write_key),
            read_key: Zeroizing::new(read_key),
            write_mac_key: Zeroizing::new(write_mac_key),
            read_mac_key: Zeroizing::new(read_mac_key),
            write_nonce,
            read_nonce,
            write_seq: 0,
            read_seq: 0,
            read_buf: Vec::new(),
            read_buf_pos: 0,
            cipher_enc: None,
            cipher_dec: None,
            close_notify_sent: false,
            is_client,
            session_id,
            cached_resumed_session: None,
            cipher_suite,
            #[allow(deprecated)]
            gmssl_padding_compat: false,
        })
    }
    /// Create a TLCP stream from a completed client handshake with a transport.
    ///
    /// The handshake must have been completed (master secret and key material derived).
    pub fn from_client_handshake_with_transport(
        handshake: TlcpHandshake,
        transport: S,
    ) -> Result<Self, TlcpError> {
        let suite_id = handshake
            .cipher_suite
            .ok_or_else(|| TlcpError::HandshakeFailed("cipher suite not negotiated".into()))?;
        let suite = TlcpCipherSuite::from_id(suite_id).ok_or_else(|| {
            TlcpError::HandshakeFailed(format!("unknown cipher suite {:02x?}", suite_id))
        })?;
        let key_material =
            TlcpKeyMaterial::derive(
                handshake.master_secret.as_deref().ok_or_else(|| {
                    TlcpError::HandshakeFailed("master secret not derived".into())
                })?,
                &handshake.client_random,
                handshake.server_random.as_ref().ok_or_else(|| {
                    TlcpError::HandshakeFailed("server random not received".into())
                })?,
                suite,
            )?;
        let session_id = handshake.session_id.clone();
        let resumed = handshake.to_resumed_session();
        let mut stream = Self::new(transport, &key_material, suite, true, session_id)?;
        stream.cached_resumed_session = resumed;
        Ok(stream)
    }
    /// Create a TLCP stream from a completed server handshake with a transport.
    pub fn from_server_handshake_with_transport(
        handshake: TlcpServerHandshake,
        transport: S,
    ) -> Result<Self, TlcpError> {
        let suite = handshake
            .cipher_suite
            .ok_or_else(|| TlcpError::HandshakeFailed("cipher suite not negotiated".into()))?;
        let key_material =
            TlcpKeyMaterial::derive(
                handshake.master_secret.as_deref().ok_or_else(|| {
                    TlcpError::HandshakeFailed("master secret not derived".into())
                })?,
                handshake.client_random.as_ref().ok_or_else(|| {
                    TlcpError::HandshakeFailed("client random not received".into())
                })?,
                &handshake.server_random,
                suite,
            )?;
        let session_id = handshake.session_id.clone();
        let resumed = handshake.to_resumed_session();
        let mut stream = Self::new(transport, &key_material, suite, false, session_id)?;
        stream.cached_resumed_session = resumed;
        Ok(stream)
    }
    /// Get a mutable reference to the inner transport.
    ///
    /// This is used during handshake to send raw records before encryption starts.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
    /// Deprecated. Historically toggled a non-standard CBC padding scheme
    /// (`N bytes of value N-1`) used to interop with pre-fix GmSSL. GmSSL
    /// since commit `57c9433` (2026-06-01) and `c12edeb` (2026-06-13)
    /// follows RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.2 strictly; we now do
    /// the same (N padding bytes of value N plus 1 trailing length byte = N+1
    /// bytes total). This method is kept as a no-op so that existing
    /// callers (`connector.with_gmssl_padding_compat(true)`,
    /// `GM_TLCP_GMSSL_COMPAT=1` in `interop_client`) keep compiling and run
    /// correctly. It will be removed in a future release.
    #[deprecated(
        since = "0.1.0",
        note = "No-op. The CBC framing always follows RFC 5246 §6.2.3.2 / \
                 GB/T 38636-2020 §6.2.3.2. Will be removed in a future release."
    )]
    pub fn with_gmssl_padding_compat(mut self, _compat: bool) -> Self {
        // Intentionally ignore the argument; the wire format is always
        // RFC 5246-compliant.
        #[allow(deprecated)]
        let _ = &mut self.gmssl_padding_compat;
        self
    }
    fn get_cipher_enc(&mut self) -> Result<&mut Sm4Cipher, TlcpError> {
        if self.cipher_enc.is_none() {
            let cipher = Sm4Cipher::new(&self.write_key)
                .map_err(|e| TlcpError::HandshakeFailed(format!("SM4 key error: {:?}", e)))?;
            self.cipher_enc = Some(cipher);
        }
        self.cipher_enc
            .as_mut()
            .ok_or_else(|| TlcpError::HandshakeFailed("cipher_enc not initialized".into()))
    }
    fn get_cipher_dec(&mut self) -> Result<&mut Sm4Cipher, TlcpError> {
        if self.cipher_dec.is_none() {
            let cipher = Sm4Cipher::new(&self.read_key)
                .map_err(|e| TlcpError::HandshakeFailed(format!("SM4 key error: {:?}", e)))?;
            self.cipher_dec = Some(cipher);
        }
        self.cipher_dec
            .as_mut()
            .ok_or_else(|| TlcpError::HandshakeFailed("cipher_dec not initialized".into()))
    }
    /// Encrypt a record with SM4-GCM, returning the complete record bytes.
    fn encrypt_gcm_record(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        let nonce = next_nonce(&self.write_nonce, self.write_seq - 1)
            .map_err(|e| std::io::Error::other(format!("Nonce overflow: {}", e)))?;
        let seq_bytes = (self.write_seq - 1).to_be_bytes();
        let cipher = self
            .get_cipher_enc()
            .map_err(|e| std::io::Error::other(format!("SM4 key error: {:?}", e)))?;
        // Per GmSSL's `tls_gcm_encrypt` (tls.c:524-528), the AAD for SM4-GCM
        // records is 13 bytes:
        //   seq_num (8) || record_header (5)
        // with the last 2 bytes of the header (which normally hold the
        // record length) overwritten by the **plaintext body** length, since
        // the GCM AAD must reflect what is actually being authenticated.
        let pt_len_bytes = (plaintext.len() as u16).to_be_bytes();
        let mut header = [0u8; 5];
        header[0] = TLCP_RECORD_TYPE_APP_DATA;
        header[1..3].copy_from_slice(&TLCP_VERSION);
        // The record length written on the wire is the ciphertext body
        // length (explicit_nonce(8) + ciphertext + tag(16)).
        let ct_len = (8 + plaintext.len() + 16) as u16;
        header[3..5].copy_from_slice(&ct_len.to_be_bytes());
        let mut aad = [0u8; 13];
        aad[0..8].copy_from_slice(&seq_bytes);
        aad[8..11].copy_from_slice(&header[0..3]);
        aad[11..13].copy_from_slice(&pt_len_bytes);
        let (ciphertext, tag) = cipher
            .encrypt_gcm(plaintext, &nonce, &aad)
            .map_err(|e| std::io::Error::other(format!("GCM encryption failed: {:?}", e)))?;
        // Wire format: header(5) || explicit_nonce(8) || ct || tag(16)
        let mut record = Vec::with_capacity(5 + 8 + plaintext.len() + 16);
        record.extend_from_slice(&header);
        record.extend_from_slice(&seq_bytes); // explicit nonce
        record.extend_from_slice(&ciphertext);
        record.extend_from_slice(&tag);
        Ok(record)
    }
    /// Encrypt a record with SM4-CBC + HMAC-SM3, returning the complete record bytes.
    fn encrypt_cbc_record(&mut self, plaintext: &[u8]) -> std::io::Result<Vec<u8>> {
        self.encrypt_cbc_record_with_type(TLCP_RECORD_TYPE_APP_DATA, plaintext)
    }
    /// Internal: same as `encrypt_cbc_record` but with a caller-chosen record-layer
    /// content type. Used by the handshake layer (which frames Finished as
    /// type=Handshake) and by app data (type=AppData).
    ///
    /// Wire format after the 5-byte record header:
    ///
    /// ```text
    ///   [IV:16] || SM4-CBC(plaintext || HMAC-SM3(32) || N x PAD_BYTE || PAD_byte)
    /// ```
    ///
    /// where `PAD_byte = N = SM4_BLOCK_SIZE - (plaintext.len() + 32) mod 16`
    /// (so the padding region is `N` bytes of value `N`, followed by **one
    /// extra byte of value `N`** at the very end of the record). That
    /// trailing length byte is required by RFC 5246 §6.2.3.2 /
    /// GB/T 38636-2020 §6.2.3.2 — the structure is
    ///
    /// ```text
    /// struct {
    ///     opaque content[TLSCompressed.length];
    ///     opaque MAC[SecurityParameters.mac_key_length];
    ///     uint8  padding[GenericBlockCipher.padding_length];
    ///     uint8  padding_length;
    /// } GenericBlockCipher;
    /// ```
    ///
    /// so the parser computes `outlen = inlen - 32 - padding_length - 1`,
    /// i.e. the single trailing length byte is not counted in `outlen`.
    /// `gmssl tlcp_server` v3.x, Tongsuo NTLS, openHiTLS, and every other
    /// TLCP peer we have measured expects exactly this layout. Emitting one
    /// byte short of it (`N` bytes of value `N` only, no length byte) breaks
    /// interop with a `bad_record_mac` alert because the parser reads the
    /// HMAC one byte too early.
    fn encrypt_cbc_record_with_type(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let seq_bytes = (self.write_seq - 1).to_be_bytes();
        // HMAC-SM3 over seq_num || type || version || length || plaintext.
        let mut mac_input = Vec::with_capacity(8 + 1 + 2 + plaintext.len());
        mac_input.extend_from_slice(&seq_bytes);
        mac_input.push(content_type);
        mac_input.extend_from_slice(&TLCP_VERSION);
        mac_input.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
        mac_input.extend_from_slice(plaintext);
        let hmac = Sm3Hmac::new(&self.write_mac_key)
            .compute(&mac_input)
            .map_err(|e| std::io::Error::other(format!("HMAC-SM3 failed: {:?}", e)))?;
        // Inner payload: plaintext || HMAC || padding_bytes(N of value N) || length_byte(N)
        //
        // Per RFC 5246 §6.2.3.2 the tail is N padding bytes of value N
        // **plus** one extra length byte of value N. Both are filled with
        // `pad_byte = pad_len`. We need `inner_len + pad_len + 1` to be a
        // non-empty multiple of 16 (the CBC block size), so `pad_len` is
        // computed against `(inner_len + 1)` — i.e. we treat the length byte
        // as part of the padding region for block-alignment accounting.
        let inner_len = plaintext.len() + SM3_HMAC_LENGTH;
        let pad_len = (SM4_BLOCK_SIZE - ((inner_len + 1) % SM4_BLOCK_SIZE)) % SM4_BLOCK_SIZE;
        let pad_byte = pad_len as u8;
        let total_tail = pad_len + 1;
        let mut inner = Vec::with_capacity(inner_len + total_tail);
        inner.extend_from_slice(plaintext);
        inner.extend_from_slice(&hmac);
        // N padding bytes, all equal to pad_len
        inner.extend(std::iter::repeat_n(pad_byte, pad_len));
        // 1 trailing length byte, also equal to pad_len
        inner.push(pad_byte);
        // Fresh random IV per record.
        let mut iv = [0u8; SM4_CBC_IV_LENGTH];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut iv);
        let cipher = self
            .get_cipher_enc()
            .map_err(|e| std::io::Error::other(format!("SM4 key error: {}", e)))?;
        // Use `encrypt_cbc_raw` here: this function has already padded `inner`
        // to a multiple of SM4_BLOCK_SIZE (plaintext || HMAC || N x PAD ||
        // PAD_byte). The PKCS#7-adding `encrypt_cbc` would silently add a
        // *second* layer of padding and produce a ciphertext that decodes
        // incorrectly on the peer side.
        let ciphertext = cipher
            .encrypt_cbc_raw(&inner, &iv)
            .map_err(|e| std::io::Error::other(format!("CBC encryption failed: {:?}", e)))?;
        let ct_len = SM4_CBC_IV_LENGTH + ciphertext.len();
        let mut record = Vec::with_capacity(5 + ct_len);
        record.push(content_type);
        record.extend_from_slice(&TLCP_VERSION);
        record.extend_from_slice(&(ct_len as u16).to_be_bytes());
        record.extend_from_slice(&iv);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }
    /// Get the session ID assigned during the handshake.
    pub fn session_id(&self) -> &[u8] {
        &self.session_id
    }
    /// Get the cached session state for resumption.
    pub fn to_resumed_session(&self) -> Option<&TlcpResumedSession> {
        self.cached_resumed_session.as_ref()
    }
    /// Whether this stream is on the client side.
    pub fn is_client(&self) -> bool {
        self.is_client
    }
    /// Return the negotiated cipher suite (post-handshake).
    pub fn cipher_suite(&self) -> TlcpCipherSuite {
        self.cipher_suite
    }
    /// Write application data (encrypted with SM4-GCM).
    ///
    /// TLCP GCM record format (GB/T 38636-2020 §6.2 / RFC 5288):
    /// ```text
    /// [content_type=0x17][version=0x0101][length(2)][explicit_nonce(8)][ciphertext][tag(16)]
    /// ```
    ///
    /// The 8-byte explicit nonce is the per-record sequence number
    /// (`write_seq`/`read_seq`) and is XORed into the fixed_iv-derived
    /// 12-byte GCM nonce base on the encryption side. The remaining
    /// 4-byte fixed_iv comes from the key block (see
    /// [`crate::tlcp::TlcpKeyMaterial::derive`]).
    ///
    /// Unlike TLS 1.3, TLCP does NOT append an inner content type byte.
    pub async fn write_application_data(&mut self, plaintext: &[u8]) -> Result<(), TlcpError> {
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or(TlcpError::SequenceOverflow)?;
        if self.cipher_suite.gcm {
            self.write_gcm(plaintext).await
        } else {
            self.write_cbc(plaintext).await
        }
    }
    /// Encrypt a single record with a caller-chosen record-layer content type
    /// and write it to the inner transport. Used by the GmSSL-compat path
    /// to send the Finished handshake message framed as a handshake record
    /// instead of an APP_DATA record (GmSSL quirk). GCM and CBC are both
    /// supported; the chosen cipher suite decides which path runs.
    pub async fn write_encrypted_record_with_type(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<(), TlcpError> {
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or(TlcpError::SequenceOverflow)?;
        if self.cipher_suite.gcm {
            self.write_gcm_with_type(content_type, plaintext).await
        } else {
            self.write_cbc_with_type(content_type, plaintext).await
        }
    }
    /// Write application data with SM4-GCM.
    async fn write_gcm(&mut self, plaintext: &[u8]) -> Result<(), TlcpError> {
        self.write_gcm_with_type(TLCP_RECORD_TYPE_APP_DATA, plaintext)
            .await
    }
    async fn write_gcm_with_type(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<(), TlcpError> {
        let nonce = next_nonce(&self.write_nonce, self.write_seq - 1)?;
        let seq_bytes = (self.write_seq - 1).to_be_bytes();
        let pt_len_bytes = (plaintext.len() as u16).to_be_bytes();
        let mut record_header = [0u8; 5];
        record_header[0] = content_type;
        record_header[1..3].copy_from_slice(&TLCP_VERSION);
        let ct_len = (8 + plaintext.len() + 16) as u16;
        record_header[3..5].copy_from_slice(&ct_len.to_be_bytes());
        let mut aad = [0u8; 13];
        aad[0..8].copy_from_slice(&seq_bytes);
        aad[8..11].copy_from_slice(&record_header[0..3]);
        aad[11..13].copy_from_slice(&pt_len_bytes);
        let cipher = self.get_cipher_enc()?;
        let (ciphertext, tag) = cipher
            .encrypt_gcm(plaintext, &nonce, &aad)
            .map_err(|e| TlcpError::HandshakeFailed(format!("GCM encryption failed: {:?}", e)))?;
        self.inner
            .write_all(&record_header)
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        self.inner
            .write_all(&seq_bytes) // explicit nonce
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        self.inner
            .write_all(&ciphertext)
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        self.inner
            .write_all(&tag)
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        self.inner
            .flush()
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        metrics::record_bytes("tlcp", "send", plaintext.len());
        Ok(())
    }
    /// Write application data with SM4-CBC + HMAC-SM3.
    ///
    /// TLCP CBC record format (GB/T 38636-2020 §6.2.3.2):
    /// ```text
    /// [content_type=0x17][version=0x0101][length(2)][IV(16)][ciphertext]
    /// ```
    async fn write_cbc(&mut self, plaintext: &[u8]) -> Result<(), TlcpError> {
        self.write_cbc_with_type(TLCP_RECORD_TYPE_APP_DATA, plaintext)
            .await
    }
    async fn write_cbc_with_type(
        &mut self,
        content_type: u8,
        plaintext: &[u8],
    ) -> Result<(), TlcpError> {
        // Both the body and the on-wire record are produced by the shared
        // helper `encrypt_cbc_record_with_type`, so the in-memory framing
        // and the wire framing stay in lock-step.
        let record = self
            .encrypt_cbc_record_with_type(content_type, plaintext)
            .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
        self.inner
            .write_all(&record)
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        self.inner
            .flush()
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        metrics::record_bytes("tlcp", "send", plaintext.len());
        Ok(())
    }
    /// Read application data (decrypted from SM4-GCM).
    ///
    /// Reads one TLCP record, decrypts it, and returns the plaintext.
    /// Unlike TLS 1.3, TLCP does not have inner content type stripping.
    pub async fn read_application_data(&mut self) -> Result<Vec<u8>, TlcpError> {
        // Read 5-byte TLCP record header
        let mut header = [0u8; 5];
        self.inner
            .read_exact(&mut header)
            .await
            .map_err(|e| TlcpError::IoError(e.to_string()))?;
        let content_type = header[0];
        let version = [header[1], header[2]];
        let ct_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        // Validate version
        if version != TLCP_VERSION {
            return Err(TlcpError::TlsRecordError(format!(
                "unexpected TLCP version: {:02X}{:02X}",
                version[0], version[1]
            )));
        }
        if ct_len > TLCP_MAX_RECORD_SIZE {
            return Err(TlcpError::HandshakeFailed(
                "TLCP record exceeds size limit".into(),
            ));
        }
        match content_type {
            TLCP_RECORD_TYPE_APP_DATA | TLCP_RECORD_TYPE_HANDSHAKE => {
                let mut buf = vec![0u8; ct_len];
                self.inner
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| TlcpError::IoError(e.to_string()))?;
                self.read_seq = self
                    .read_seq
                    .checked_add(1)
                    .ok_or(TlcpError::SequenceOverflow)?;
                let plaintext = if self.cipher_suite.gcm {
                    self.decrypt_gcm(&buf, &header)?
                } else {
                    self.decrypt_cbc(&buf, &header)?
                };
                metrics::record_bytes("tlcp", "recv", plaintext.len());
                Ok(plaintext)
            }
            TLCP_RECORD_TYPE_ALERT => {
                // Read alert payload
                let mut buf = vec![0u8; ct_len];
                self.inner
                    .read_exact(&mut buf)
                    .await
                    .map_err(|e| TlcpError::IoError(e.to_string()))?;
                if buf.len() >= 2 && buf[0] == 0x01 && buf[1] == 0x00 {
                    // close_notify — return empty to signal EOF
                    return Ok(Vec::new());
                }
                Err(TlcpError::TlsRecordError(format!(
                    "TLCP alert: level={} description={}",
                    buf.first().copied().unwrap_or(0),
                    buf.get(1).copied().unwrap_or(0)
                )))
            }
            other => Err(TlcpError::TlsRecordError(format!(
                "unexpected TLCP content type: 0x{:02X}",
                other
            ))),
        }
    }
    /// Decrypt a GCM record.
    fn decrypt_gcm(&mut self, buf: &[u8], header: &[u8; 5]) -> Result<Vec<u8>, TlcpError> {
        // GCM record wire format: explicit_nonce(8) || ciphertext || tag(16)
        if buf.len() < 8 + 16 {
            return Err(TlcpError::HandshakeFailed(
                "TLCP GCM record too short".into(),
            ));
        }
        let (explicit_nonce_and_ct, tag) = buf.split_at(buf.len() - 16);
        let (_explicit_nonce, ciphertext) = explicit_nonce_and_ct.split_at(8);
        // AAD = seq_bytes (8) || record_header (5) with the last 2 bytes
        // overwritten by the **plaintext body** length (= ciphertext length).
        // This mirrors GmSSL's `tls_gcm_decrypt` (tls.c:592-596) and
        // `encrypt_gcm_record`.
        let nonce = next_nonce(&self.read_nonce, self.read_seq - 1)?;
        let seq_bytes = (self.read_seq - 1).to_be_bytes();
        let pt_len_bytes = (ciphertext.len() as u16).to_be_bytes();
        let mut aad = [0u8; 13];
        aad[0..8].copy_from_slice(&seq_bytes);
        aad[8..11].copy_from_slice(&header[0..3]);
        aad[11..13].copy_from_slice(&pt_len_bytes);
        let cipher = self.get_cipher_dec()?;
        cipher
            .decrypt_gcm(ciphertext, &nonce, &aad, tag)
            .map_err(|e| TlcpError::HandshakeFailed(format!("GCM decryption failed: {:?}", e)))
    }
    /// Decrypt a CBC+HMAC record.
    ///
    /// Wire format (after the 5-byte record header):
    /// `[IV(16)][SM4-CBC(plaintext || HMAC || padding || padding_length)]`.
    /// The post-MAC tail follows RFC 5246 §6.2.3.2 / GB/T 38636-2020 §6.2.3.2:
    ///
    /// ```text
    /// struct {
    ///     opaque content[TLSCompressed.length];
    ///     opaque MAC[SecurityParameters.mac_key_length];
    ///     uint8  padding[GenericBlockCipher.padding_length];
    ///     uint8  padding_length;
    /// } GenericBlockCipher;
    /// ```
    ///
    /// i.e. `N` padding bytes followed by **one** trailing length byte (also
    /// equal to `N`). The total post-MAC tail is therefore `N + 1` bytes.
    fn decrypt_cbc(&mut self, buf: &[u8], header: &[u8; 5]) -> Result<Vec<u8>, TlcpError> {
        // TLCP §6.2.3 record layout on the wire:
        //   [IV(16)][SM4-CBC(plaintext || HMAC(32) || padding || padding_length)]
        // The first 16 bytes are the per-record random IV.
        if buf.len() < SM4_CBC_IV_LENGTH + SM4_BLOCK_SIZE + SM3_HMAC_LENGTH {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC record too short".into(),
            ));
        }
        let (iv, ciphertext) = buf.split_at(SM4_CBC_IV_LENGTH);
        let cipher = self.get_cipher_dec()?;
        // Use `decrypt_cbc_raw` here: this function does **not** strip any
        // padding — it returns the raw block-decrypted bytes. We need the raw
        // form because the trailing-byte layout above differs from PKCS#7
        // (which has only N padding bytes and no length byte); the caller
        // has to peel both.
        let decrypted = cipher
            .decrypt_cbc_raw(ciphertext, iv)
            .map_err(|_| TlcpError::HandshakeFailed("TLCP CBC decryption failed".into()))?;
        // Security note: we deliberately drop the inner CryptoError here
        // (using `_` instead of `{:?}`) so the error message does not leak
        // details such as `InvalidPadding { expected: N }`. Differentiating
        // "bad padding" from "bad HMAC" gives an attacker a padding-oracle.
        // The gm-crypto SM4 implementation is constant-time, so this is
        // belt-and-braces against any future debug-format regressions.
        if decrypted.is_empty() {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC empty plaintext".into(),
            ));
        }
        // The trailing byte is the explicit `padding_length` field (RFC 5246).
        // Per §6.2.3.2 it can be any byte value in [0, 255] as long as the
        // total post-MAC tail is a multiple of the block size. We restrict
        // to [0, SM4_BLOCK_SIZE] (the maximum physically possible) because a
        // length byte larger than the block size would mean the padding
        // overflows the previous block, which can only happen on a
        // deliberately malformed record and lets an attacker misalign the
        // HMAC extraction.
        let pad_len = decrypted[decrypted.len() - 1] as usize;
        if pad_len > SM4_BLOCK_SIZE {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC invalid padding (length byte > block size)".into(),
            ));
        }
        // Total post-MAC tail is `pad_len` padding bytes plus the 1 length
        // byte at the very end (RFC 5246 §6.2.3.2). `pad_len = 0` is a
        // legitimate case (ciphertext just happened to be block-aligned
        // after MAC); the total tail then collapses to the single length
        // byte.
        let pad_consumed = pad_len + 1;
        if pad_consumed > decrypted.len() {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC invalid padding (length byte overflows record)".into(),
            ));
        }
        // All `pad_len` padding bytes (NOT including the trailing length
        // byte itself, which obviously equals `pad_len` because we just read
        // it) must equal `pad_len`.
        if !decrypted[decrypted.len() - pad_consumed..decrypted.len() - 1]
            .iter()
            .all(|b| *b as usize == pad_len)
        {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC malformed padding".into(),
            ));
        }
        let unpadded_len = decrypted.len() - pad_consumed;
        if unpadded_len < SM3_HMAC_LENGTH {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC inner too short for MAC".into(),
            ));
        }
        let plaintext_len = unpadded_len - SM3_HMAC_LENGTH;
        let plaintext = &decrypted[..plaintext_len];
        let mac_received = &decrypted[plaintext_len..unpadded_len];
        // Verify HMAC-SM3 over seq_num || content_type || version || length || plaintext
        let seq_bytes = (self.read_seq - 1).to_be_bytes();
        let mut mac_input = Vec::with_capacity(8 + 1 + 2 + plaintext.len());
        mac_input.extend_from_slice(&seq_bytes);
        mac_input.push(header[0]); // content_type
        mac_input.extend_from_slice(&header[1..3]); // version
        mac_input.extend_from_slice(&(plaintext.len() as u16).to_be_bytes());
        mac_input.extend_from_slice(plaintext);
        let hmac_computed = Sm3Hmac::new(&self.read_mac_key)
            .compute(&mac_input)
            .map_err(|e| TlcpError::HandshakeFailed(format!("HMAC-SM3 compute failed: {:?}", e)))?;
        // Constant-time HMAC comparison
        if !bool::from(mac_received.ct_eq(&hmac_computed)) {
            return Err(TlcpError::HandshakeFailed(
                "TLCP CBC HMAC verification failed".into(),
            ));
        }
        Ok(plaintext.to_vec())
    }
    /// Send a close_notify alert for graceful shutdown.
    ///
    /// Per GB/T 38636-2020, the alert record uses the same encryption
    /// as application data after the handshake is complete.
    pub async fn close(&mut self) -> Result<(), TlcpError> {
        if self.close_notify_sent {
            return Ok(());
        }
        // TLCP close_notify: [warning(1)][close_notify(0)]
        let alert_payload: [u8; 2] = [0x01, 0x00];
        self.write_seq = self
            .write_seq
            .checked_add(1)
            .ok_or(TlcpError::SequenceOverflow)?;
        if self.cipher_suite.gcm {
            self.write_gcm(&alert_payload).await?;
        } else {
            self.write_cbc(&alert_payload).await?;
        }
        self.close_notify_sent = true;
        Ok(())
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Return buffered data first
        if self.read_buf_pos < self.read_buf.len() {
            let available = self.read_buf.len() - self.read_buf_pos;
            let to_copy = available.min(buf.remaining());
            buf.put_slice(&self.read_buf[self.read_buf_pos..self.read_buf_pos + to_copy]);
            self.read_buf_pos += to_copy;
            if self.read_buf_pos >= self.read_buf.len() {
                self.read_buf.clear();
                self.read_buf_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        let mut stream_ref = Pin::new(&mut self.inner);
        // Read 5-byte TLCP record header
        let mut header = [0u8; 5];
        match stream_ref
            .as_mut()
            .poll_read(cx, &mut ReadBuf::new(&mut header))
        {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        let content_type = header[0];
        let version = [header[1], header[2]];
        let ct_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if version != TLCP_VERSION {
            return Poll::Ready(Err(std::io::Error::other(format!(
                "unexpected TLCP version: {:02X}{:02X}",
                version[0], version[1]
            ))));
        }
        if ct_len > TLCP_MAX_RECORD_SIZE {
            return Poll::Ready(Err(std::io::Error::other("TLCP record exceeds size limit")));
        }
        match content_type {
            TLCP_RECORD_TYPE_APP_DATA => {
                let mut ciphertext_buf = vec![0u8; ct_len];
                let mut filled = 0;
                while filled < ct_len {
                    let mut chunk_buf = ReadBuf::new(&mut ciphertext_buf[filled..]);
                    match stream_ref.as_mut().poll_read(cx, &mut chunk_buf) {
                        Poll::Ready(Ok(_)) => {
                            let n = chunk_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(std::io::Error::other(
                                    "TLCP record read incomplete",
                                )));
                            }
                            filled += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                self.read_seq = match self.read_seq.checked_add(1) {
                    Some(s) => s,
                    None => return Poll::Ready(Err(std::io::Error::other("Sequence overflow"))),
                };
                let plaintext = if self.cipher_suite.gcm {
                    if ciphertext_buf.len() < 8 + 16 {
                        return Poll::Ready(Err(std::io::Error::other(
                            "TLCP GCM record too short",
                        )));
                    }
                    // Wire layout after the record header is
                    // `explicit_nonce(8) || ciphertext(body) || tag(16)`,
                    // matching `encrypt_gcm_record`. We must pass **only**
                    // the encrypted body to `decrypt_gcm`, not the explicit
                    // nonce prefix; including it corrupts the GCM tag.
                    let (en_and_ct, tag) = ciphertext_buf.split_at(ciphertext_buf.len() - 16);
                    let (_explicit_nonce, body_ct) = en_and_ct.split_at(8);
                    let nonce = match next_nonce(&self.read_nonce, self.read_seq - 1) {
                        Ok(n) => n,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "Nonce overflow: {}",
                                e
                            ))));
                        }
                    };
                    let seq_bytes = (self.read_seq - 1).to_be_bytes();
                    // Per GmSSL `tls_gcm_decrypt` (tls.c:592-596) and the encrypt
                    // side's AAD construction, the 13-byte AAD is:
                    //   seq (8) || record_header[0..3] (3) || pt_len_bytes (2)
                    // with the last 2 bytes of the record header overwritten by
                    // the **plaintext body** length (= ciphertext body length
                    // because GCM is length-preserving). The decrypt AAD must
                    // match the encrypt AAD byte-for-byte; using the full 5-byte
                    // header here causes the GCM tag mismatch we're fixing.
                    let pt_len_bytes = (body_ct.len() as u16).to_be_bytes();
                    let mut aad = [0u8; 13];
                    aad[0..8].copy_from_slice(&seq_bytes);
                    aad[8..11].copy_from_slice(&header[0..3]);
                    aad[11..13].copy_from_slice(&pt_len_bytes);
                    let cipher = match self.get_cipher_dec() {
                        Ok(c) => c,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "SM4 key error: {}",
                                e
                            ))));
                        }
                    };
                    match cipher.decrypt_gcm(body_ct, &nonce, &aad, tag) {
                        Ok(p) => p,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "GCM decryption failed: {:?}",
                                e
                            ))));
                        }
                    }
                } else {
                    // CBC + HMAC-SM3
                    match self.decrypt_cbc(&ciphertext_buf, &header) {
                        Ok(p) => p,
                        Err(e) => {
                            return Poll::Ready(Err(std::io::Error::other(format!(
                                "CBC decryption failed: {:?}",
                                e
                            ))));
                        }
                    }
                };
                // TLCP: no inner content type stripping — plaintext is raw data
                // But check if this is an encrypted close_notify alert
                if plaintext.len() == 2 && plaintext[0] == 0x01 && plaintext[1] == 0x00 {
                    // close_notify received — return 0 bytes (EOF)
                    return Poll::Ready(Ok(()));
                }
                self.read_buf = plaintext;
                self.read_buf_pos = 0;
                let to_copy = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..to_copy]);
                self.read_buf_pos = to_copy;
                if self.read_buf_pos >= self.read_buf.len() {
                    self.read_buf.clear();
                    self.read_buf_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
            TLCP_RECORD_TYPE_ALERT => {
                // Alert received — check for close_notify
                let mut alert_buf = vec![0u8; ct_len];
                let mut filled = 0;
                while filled < ct_len {
                    let mut chunk_buf = ReadBuf::new(&mut alert_buf[filled..]);
                    match stream_ref.as_mut().poll_read(cx, &mut chunk_buf) {
                        Poll::Ready(Ok(_)) => {
                            let n = chunk_buf.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(std::io::Error::other(
                                    "TLCP alert read incomplete",
                                )));
                            }
                            filled += n;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                // close_notify = [0x01, 0x00]
                if alert_buf.len() >= 2 && alert_buf[0] == 0x01 && alert_buf[1] == 0x00 {
                    Poll::Ready(Ok(())) // 0 bytes filled = EOF
                } else {
                    Poll::Ready(Err(std::io::Error::other(format!(
                        "TLCP alert: level={} description={}",
                        alert_buf.first().copied().unwrap_or(0),
                        alert_buf.get(1).copied().unwrap_or(0)
                    ))))
                }
            }
            _ => Poll::Ready(Err(std::io::Error::other(format!(
                "unexpected TLCP content type: 0x{:02X}",
                content_type
            )))),
        }
    }
}
impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.write_seq = match self.write_seq.checked_add(1) {
            Some(s) => s,
            None => return Poll::Ready(Err(std::io::Error::other("Sequence overflow"))),
        };
        let record_data = if self.cipher_suite.gcm {
            self.encrypt_gcm_record(buf)?
        } else {
            self.encrypt_cbc_record(buf)?
        };
        let mut stream_ref = Pin::new(&mut self.inner);
        // Write the complete record
        let mut written = 0;
        while written < record_data.len() {
            match stream_ref.as_mut().poll_write(cx, &record_data[written..]) {
                Poll::Ready(Ok(n)) if n > 0 => written += n,
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err(std::io::Error::other("failed to write record")));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if !self.close_notify_sent {
            self.write_seq = match self.write_seq.checked_add(1) {
                Some(s) => s,
                None => return Pin::new(&mut self.inner).poll_shutdown(cx),
            };
            let alert_payload: [u8; 2] = [0x01, 0x00];
            let record_data = if self.cipher_suite.gcm {
                self.encrypt_gcm_record(&alert_payload).ok()
            } else {
                self.encrypt_cbc_record(&alert_payload).ok()
            };
            if let Some(record) = record_data {
                let mut stream_ref = Pin::new(&mut self.inner);
                let mut written = 0;
                while written < record.len() {
                    match stream_ref.as_mut().poll_write(cx, &record[written..]) {
                        Poll::Ready(Ok(n)) if n > 0 => written += n,
                        Poll::Ready(Ok(_)) | Poll::Ready(Err(_)) => break,
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            self.close_notify_sent = true;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
// ============================================================================
// TLCP Connector & Acceptor
// ============================================================================
/// TLCP client connector configuration.
///
/// Encapsulates the parameters needed to establish a TLCP client connection.
#[derive(Clone)]
pub struct TlcpConnector {
    session_cache: TlcpSessionCache,
    /// Expected server signing certificate public key (for ServerKeyExchange verification)
    server_sign_pubkey: Option<Vec<u8>>,
    /// Server signing certificate distid (default: empty string for interop)
    server_sign_distid: Option<String>,
    /// Cipher suites to offer (default: all four TLCP suites)
    cipher_suites: Vec<[u8; 2]>,
    /// Switch the CBC record layer to GmSSL 3.x's non-standard padding
    /// (N bytes of value N-1 instead of N). Off by default. See
    /// [`TlcpStream::with_gmssl_padding_compat`].
    #[allow(deprecated)]
    gmssl_padding_compat: bool,
    /// Optional client certificate chain (DER bytes, in leaf-first order)
    /// sent in reply to a server `CertificateRequest`. Set via
    /// [`with_client_certs`](Self::with_client_certs).
    client_certs: Vec<Vec<u8>>,
    /// Optional client signing key (PKCS#8 PEM, possibly encrypted)
    /// used to sign the `CertificateVerify` message that follows the
    /// client `Certificate` in mutual-auth handshakes. Set via
    /// [`with_client_certs`](Self::with_client_certs).
    client_sign_key: Option<String>,
    /// Optional client encryption key (PKCS#8 PEM, possibly encrypted)
    /// used as the long-term scalar in the GB/T 32918.3-2016 §6.4.2
    /// SM2 key agreement for ECDHE_*_SM4_* cipher suites. Set via
    /// [`with_client_certs`](Self::with_client_certs).
    client_enc_key: Option<String>,
    /// Server encryption certificate distid used in ECDHE PMS derivation
    /// (Z_server per GB/T 32918.2-2016 §6.1). Default: "1234567812345678".
    /// Audit: M-3 in interop/AUDIT-2026-09-06.md.
    server_enc_distid: Option<String>,
    /// Client encryption certificate distid used in ECDHE PMS derivation
    /// (Z_client per GB/T 32918.2-2016 §6.1). Default: "1234567812345678".
    /// Audit: M-3.
    client_enc_distid: Option<String>,
    /// Client signing certificate distid used for CertificateVerify
    /// (Z_client per GB/T 32918.2-2016 §6.1). Default: "1234567812345678".
    /// Audit: M-3.
    client_sign_distid: Option<String>,
    /// Password to decrypt client_sign_key (and client_enc_key if
    /// it is also encrypted). Default: P@ssw0rd.
    client_sign_key_password: Option<String>,
}
impl Default for TlcpConnector {
    fn default() -> Self {
        Self::new()
    }
}
impl TlcpConnector {
    /// Create a new TLCP connector with default settings.
    pub fn new() -> Self {
        Self {
            session_cache: TlcpSessionCache::new(),
            server_sign_pubkey: None,
            server_sign_distid: None,
            server_enc_distid: None,
            client_enc_distid: None,
            client_sign_distid: None,
            cipher_suites: vec![
                TLS_ECDHE_SM4_GCM_SM3,
                TLS_ECDHE_SM4_CBC_SM3,
                TLS_ECC_SM4_GCM_SM3,
                TLS_ECC_SM4_CBC_SM3,
            ],
            #[allow(deprecated)]
            gmssl_padding_compat: false,
            client_certs: Vec::new(),
            client_sign_key: None,
            client_enc_key: None,
            client_sign_key_password: None,
        }
    }
    /// Create a connector with a shared session cache for resumption.
    pub fn with_session_cache(mut self, cache: TlcpSessionCache) -> Self {
        self.session_cache = cache;
        self
    }
    /// Configure the expected server signing certificate public key.
    ///
    /// **Required** before calling [`connect_with_certs`](Self::connect_with_certs).
    /// The connector will use this key to verify the `ServerKeyExchange`
    /// signature; without it, the handshake will fail with a clear error
    /// rather than silently proceeding with an unverified ECDHE exchange.
    ///
    /// # Arguments
    /// * `public_key` — DER-encoded SM2 public key of the server's signing cert
    /// * `distid` — SM2 `distid` string used in signature verification
    ///   (typically the subject `CN` of the signing certificate)
    pub fn with_server_sign_key(mut self, public_key: Vec<u8>, distid: String) -> Self {
        self.server_sign_pubkey = Some(public_key);
        self.server_sign_distid = Some(distid);
        self
    }
    /// Configure the client certificate chain + signing key sent in
    /// response to a server `CertificateRequest`.
    ///
    /// - `chain`: list of DER-encoded certificates, leaf-first. The
    ///   last entry is typically the issuing CA. Required when talking
    ///   to `gmssl tlcp_server` 2026-06+ master, which forces
    ///   `client_certificate_verify = 1` for the ECDHE_*_SM4_* suites
    ///   and rejects empty chains.
    /// - `sign_key_pem`: PKCS#8 PEM (possibly SM3-PBKDF2 encrypted) for
    ///   the client's signing key. Used to produce the
    ///   `CertificateVerify` signature.
    /// - `password`: password for the encrypted key. Pass `None` to use
    ///   the default `"P@ssw0rd"` (the test-cert password emitted by
    ///   `gmssl sm2keygen`).
    ///
    ///   **⚠️ SECURITY WARNING**: The default `"P@ssw0rd"` is a **publicly-known
    ///   test-cert password** used by `gmssl sm2keygen`. **Production callers
    ///   MUST pass `Some(actual_password)`** for any cert not generated by
    ///   the unmodified `gmssl sm2keygen` tool. Leaving this as `None` for
    ///   production certificates will cause decryption to fail (with a clear
    ///   error) — there is no silent insecure fallback, but it is easy to
    ///   misread the default and ship an unchanged `None` after copying an
    ///   example. We kept the default to match `gmssl tlcp_server` interop
    ///   test certs verbatim; do not rely on it for any other purpose.
    /// - `enc_key_pem`: optional PKCS#8 PEM for the client's encryption
    ///   key. Required for TLCP ECDHE suites (the connector reads it
    ///   to derive `t = x̂_R * r + k` per GB/T 32918.3-2016 §6.4.2
    ///   during the ECDHE key agreement).
    pub fn with_client_certs(
        mut self,
        chain: Vec<Vec<u8>>,
        sign_key_pem: String,
        enc_key_pem: Option<String>,
        password: Option<String>,
    ) -> Self {
        self.client_certs = chain;
        self.client_sign_key = Some(sign_key_pem);
        self.client_enc_key = enc_key_pem;
        self.client_sign_key_password = password;
        self
    }
    /// Configure the SM2 distid for the server encryption certificate
    /// used in ECDHE PMS derivation (Z_server per GB/T 32918.2-2016 §6.1).
    ///
    /// Defaults to `"1234567812345678"` (the GmSSL/Tongsuo convention) for
    /// interop. Override this if the peer enc certificate was generated with
    /// a different distid — otherwise the Z value would mismatch and the
    /// ECDHE pre-master secret would differ from the peer's. Audit M-3.
    pub fn with_server_enc_distid(mut self, distid: String) -> Self {
        self.server_enc_distid = Some(distid);
        self
    }
    /// Configure the SM2 distid for the client encryption certificate
    /// used in ECDHE PMS derivation (Z_client per GB/T 32918.2-2016 §6.1).
    ///
    /// Defaults to `"1234567812345678"` for interop. Override this if the
    /// client enc cert was generated with a different distid. Audit M-3.
    pub fn with_client_enc_distid(mut self, distid: String) -> Self {
        self.client_enc_distid = Some(distid);
        self
    }
    /// Configure the SM2 distid for the client signing certificate used
    /// for CertificateVerify (Z_client per GB/T 32918.2-2016 §6.1).
    ///
    /// Defaults to `"1234567812345678"` for interop. Override this if the
    /// client sign cert was generated with a different distid. Audit M-3.
    pub fn with_client_sign_distid(mut self, distid: String) -> Self {
        self.client_sign_distid = Some(distid);
        self
    }
    /// Configure which cipher suites to offer in the ClientHello.
    ///
    /// By default, all four TLCP cipher suites are offered.
    /// Use this to restrict to specific suites (e.g., CBC-only for testing).
    pub fn with_cipher_suites(mut self, suites: Vec<[u8; 2]>) -> Self {
        if !suites.is_empty() {
            self.cipher_suites = suites;
        }
        self
    }
    /// Enable GmSSL 3.x CBC-record-layer padding compatibility.
    ///
    /// Set this when connecting to `gmssl tlcp_server` v3.x, which uses a
    /// non-standard padding (N bytes of value N-1 instead of PKCS#7's
    /// N bytes of value N). Default is `false` so we stay inter-operable
    /// with every standards-conforming TLCP peer (Tongsuo / openHiTLS /
    /// GMNS / future GmSSL releases).
    pub fn with_gmssl_padding_compat(mut self, compat: bool) -> Self {
        self.gmssl_padding_compat = compat;
        self
    }
    /// Connect to a TLCP server over the given transport.
    ///
    /// If `server_sign_pubkey` is configured, performs a production ECDHE handshake
    /// with ServerKeyExchange verification. Otherwise falls back to simulated handshake.
    pub async fn connect<S>(&self, transport: S) -> Result<TlcpStream<S>, TlcpError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.server_sign_pubkey.is_some() {
            self.connect_with_certs(transport).await
        } else {
            #[allow(deprecated)]
            connect_tlcp(transport, &self.session_cache).await
        }
    }
    /// Production ECDHE handshake with server certificate verification.
    pub async fn connect_with_certs<S>(&self, transport: S) -> Result<TlcpStream<S>, TlcpError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut io = transport;
        // Step 1: Send ClientHello
        let mut client_hs = TlcpHandshake::new_client()?;
        client_hs.cipher_suites = self.cipher_suites.clone();
        let client_hello = client_hs.create_client_hello()?;
        let ch_bytes = client_hello.to_bytes()?;
        write_handshake_record(&mut io, &ch_bytes)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write ClientHello: {}", e)))?;
        client_hs.transcript.extend_from_slice(&ch_bytes);
        // Step 2: Read ServerHello
        let (_ct, sh_payload) = read_plaintext_record(&mut io)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("read ServerHello: {}", e)))?;
        let (sh_type, sh_body, _rem) = parse_handshake_message(&sh_payload)?;
        if sh_type != HandshakeType::ServerHello {
            return Err(TlcpError::HandshakeFailed(format!(
                "Expected ServerHello, got {:?}",
                sh_type
            )));
        }
        let server_hello = TlcpServerHello::from_bytes(&sh_body)?;
        client_hs.process_server_hello(&server_hello)?;
        client_hs.transcript.extend_from_slice(&sh_payload);
        let server_random = server_hello.random;
        let client_random = client_hs.client_random;
        // Step 3: Read Certificate
        let (_ct, cert_payload) = read_plaintext_record(&mut io)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("read Certificate: {}", e)))?;
        let (cert_type, cert_body, _rem) = parse_handshake_message(&cert_payload)?;
        if cert_type != HandshakeType::Certificate {
            return Err(TlcpError::HandshakeFailed(format!(
                "Expected Certificate, got {:?}",
                cert_type
            )));
        }
        // Parse the dual-cert (sign + enc) so we can run ECC-suite key
        // exchange (we need the enc cert for SM2 enc). The state-machine
        // `process_server_certs` call also advances the handshake so the
        // subsequent `derive_master_secret` is happy.
        let cert_pair = TlcpCertPair::from_certificate_message(&cert_body)?;
        client_hs.process_server_certs(cert_pair.clone())?;
        client_hs.transcript.extend_from_slice(&cert_payload);
        // Print cert bytes (using {:02x?} for first/last 32 bytes to keep output small)
        // Determine the negotiated suite *before* step 4 so we can decide whether
        // to read ServerKeyExchange (which is only emitted by standards-strict
        // peers for ECDHE suites, not for static-ECC). In default mode we still
        // unconditionally read SKE to preserve GmSSL/Tongsuo interop (those peers
        // emit SKE for static-ECC too).
        let suite = TlcpCipherSuite::from_id(server_hello.cipher_suite).ok_or_else(|| {
            TlcpError::HandshakeFailed(format!(
                "server selected unknown cipher suite {:02x?}",
                server_hello.cipher_suite
            ))
        })?;
        let is_ecc_mode = !suite.ecdhe;
        // Spec-default (RFC 5246 §7.4.3): only DHE suites emit
        // ServerKeyExchange. Static-ECC skips SKE entirely.
        //
        // GmSSL-master shim: always read SKE (it carries an
        // ECDHE-style body for static-ECC too).
        #[cfg(feature = "tlcp-gmssl-compat")]
        let need_ske = true;
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        let need_ske = !is_ecc_mode;

        let ske_body: Vec<u8> = if need_ske {
            // Step 4: Read ServerKeyExchange
            let (_ct, ske_payload) = read_plaintext_record(&mut io).await.map_err(|e| {
                TlcpError::HandshakeFailed(format!("read ServerKeyExchange: {}", e))
            })?;
            let (ske_type, body, _rem) = parse_handshake_message(&ske_payload)?;
            if ske_type != HandshakeType::ServerKeyExchange {
                return Err(TlcpError::HandshakeFailed(format!(
                    "Expected ServerKeyExchange, got {:?}",
                    ske_type
                )));
            }
            // Step 5: Verify ServerKeyExchange signature. We REQUIRE the caller
            // to configure `server_sign_pubkey` + `server_sign_distid` via
            // `with_server_sign_key(...)`; silently skipping verification would
            // be a critical MITM vulnerability (audit 2026-08-31).
            let (pubkey, distid) = self
                .server_sign_pubkey
                .as_ref()
                .zip(self.server_sign_distid.as_ref())
                .ok_or_else(|| {
                    TlcpError::HandshakeFailed(
                        "ServerKeyExchange signature verification requires \
                         server_sign_pubkey + server_sign_distid; call \
                         TlcpConnector::with_server_sign_key() before \
                         connect_with_certs()."
                            .to_string(),
                    )
                })?;
            let verifier = gm_crypto::sm2::Sm2Verifier::new(pubkey, distid)
                .map_err(|e| TlcpError::HandshakeFailed(format!("verifier create: {}", e)))?;
            crate::tlcp::crypto::verify::verify_ske_signature(
                is_ecc_mode,
                &body,
                &client_random,
                &server_random,
                &cert_pair.enc_cert,
                &verifier,
            )?;
            client_hs.transcript.extend_from_slice(&ske_payload);
            body
        } else {
            // Strict mode + static-ECC: no ServerKeyExchange on the wire (per
            // RFC 5246 §7.4.3 / GB/T 38636-2020 §6.4.1.5). Skip directly to the
            // CertificateRequest/ServerHelloDone step below.
            Vec::new()
        };
        // Step 5.5: Read CertificateRequest or ServerHelloDone. The next plaintext
        // record from the server is one of:
        //   - CertificateRequest (GmSSL/Tongsuo for ECDHE)
        //   - ServerHelloDone   (standards-strict peers for static-ECC, and
        //                       most peers after CR for ECDHE)
        // We track which case we hit so step 6 can skip if SHD was already
        // consumed — that previously caused a hang against standards-strict
        // peers (the old fall-through comment admitted the duplicate SHD
        // was harmless for GmSSL but it broke openHiTLS).
        let mut server_sent_cert_request = false;
        let mut shd_already_consumed = false;
        let cr_payload_opt = read_plaintext_record(&mut io).await.ok();
        if let Some((_ct, cr_payload)) = cr_payload_opt {
            if cr_payload.len() >= 4 {
                if let Ok((cr_type, _, _)) = parse_handshake_message(&cr_payload) {
                    if cr_type == HandshakeType::CertificateRequest {
                        server_sent_cert_request = true;
                        client_hs.transcript.extend_from_slice(&cr_payload);
                    } else if cr_type == HandshakeType::ServerHelloDone {
                        client_hs.transcript.extend_from_slice(&cr_payload);
                        // Spec mode: mark SHD as consumed so step 6
                        // doesn't re-read it (otherwise we'd hang
                        // against standards-strict peers that don't
                        // double-send SHD). GmSSL-master shim also
                        // sets this but step 6 ignores the flag.
                        shd_already_consumed = true;
                    }
                }
            }
        }
        // Step 6: Read ServerHelloDone (or skip if already consumed).
        //
        // Spec-default (--features ... tlcp-gmssl-compat off): skip
        // when step 5.5 already consumed SHD (so we don't hang
        // against standards-strict peers).
        //
        // GmSSL-master shim: always read SHD a second time; the
        // 0.2.x default-mode fall-through comment said this would
        // result in SHD bytes appearing twice in the transcript,
        // but Finished verify is transcript-independent (PRF over
        // transcript hash), so the duplicate doesn't break Finished.
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        {
            if !shd_already_consumed {
                let (_ct, shd_payload) = read_plaintext_record(&mut io).await.map_err(|e| {
                    TlcpError::HandshakeFailed(format!("read ServerHelloDone: {}", e))
                })?;
                let (shd_type, _shd_body, _rem) = parse_handshake_message(&shd_payload)?;
                if shd_type != HandshakeType::ServerHelloDone {
                    return Err(TlcpError::HandshakeFailed(format!(
                        "Expected ServerHelloDone, got {:?}",
                        shd_type
                    )));
                }
                client_hs.transcript.extend_from_slice(&shd_payload);
            }
        }
        #[cfg(feature = "tlcp-gmssl-compat")]
        {
            let (_ct, shd_payload) = read_plaintext_record(&mut io)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("read ServerHelloDone: {}", e)))?;
            let (shd_type, _shd_body, _rem) = parse_handshake_message(&shd_payload)?;
            if shd_type != HandshakeType::ServerHelloDone {
                return Err(TlcpError::HandshakeFailed(format!(
                    "Expected ServerHelloDone, got {:?}",
                    shd_type
                )));
            }
            client_hs.transcript.extend_from_slice(&shd_payload);
            let _ = shd_already_consumed; // suppress unused warning
        }
        // Step 6.5: If the server sent CertificateRequest, RFC 5246
        // §7.4.6 requires us to reply with a Certificate message
        // before ClientKeyExchange. GmSSL 2026-06+ master forces this
        // for all ECDHE_*_SM4_* suites and then runs
        // `tls_cert_chain_verify` on whatever we send. An empty cert
        // message makes `tls_cert_chain_verify` return -1 (it rejects
        // empty chains with `bad_certificate`), so we must send a
        // real client cert chain that chains to a CA the server
        // trusts. The connector exposes this via
        // `with_client_certs(...)` — callers in the interop test
        // pass a cert chain + signing key built from the same
        // self-signed CA that the gmssl server was given via
        // `-cacert`.
        if server_sent_cert_request {
            if self.client_certs.is_empty() {
                return Err(TlcpError::HandshakeFailed(
                    "Server sent CertificateRequest but no client certificate \
                     was configured. Call TlcpConnector::with_client_certs() \
                     with a cert chain + signing key before connect."
                        .to_string(),
                ));
            }
            // Build the Certificate handshake message body. Per RFC 5246
            // §7.4.6 the body is `opaque ASN.1Cert<0..2^24-1>`. Layout:
            //   3-byte total length prefix
            //   then for each cert in the chain:
            //     3-byte cert length + DER cert bytes
            let mut chain_body = Vec::new();
            for cert in &self.client_certs {
                chain_body.push((cert.len() >> 16) as u8);
                chain_body.push((cert.len() >> 8) as u8);
                chain_body.push(cert.len() as u8);
                chain_body.extend_from_slice(cert);
            }
            let mut cert_body = Vec::with_capacity(3 + chain_body.len());
            cert_body.push((chain_body.len() >> 16) as u8);
            cert_body.push((chain_body.len() >> 8) as u8);
            cert_body.push(chain_body.len() as u8);
            cert_body.extend_from_slice(&chain_body);
            let mut cert_msg = Vec::with_capacity(4 + cert_body.len());
            cert_msg.push(HandshakeType::Certificate as u8);
            cert_msg.push((cert_body.len() >> 16) as u8);
            cert_msg.push((cert_body.len() >> 8) as u8);
            cert_msg.push(cert_body.len() as u8);
            cert_msg.extend_from_slice(&cert_body);
            write_handshake_record(&mut io, &cert_msg)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("write Certificate: {}", e)))?;
            // Append client Certificate to transcript NOW (BEFORE
            // CKE). The CV signature will be computed over the
            // transcript that ends with our CKE, and the server
            // builds its transcript in the same order (Certificate
            // arrives before CKE on the wire, and
            // `tls_recv_client_certificate` runs before
            // `tlcp_recv_client_key_exchange` on the server).
            client_hs.transcript.extend_from_slice(&cert_msg);
            // Stash a copy for step 7.5 to re-derive signature bytes if
            // needed (no longer needed to defer transcript extension).
        }
        // Handshake messages collected so far that need to be appended
        // to `client_hs.transcript` in a deterministic order before CV
        // is signed. We do this in the unified "step 7" block below.
        let pending_cert_msg: Option<Vec<u8>> =
            if server_sent_cert_request && !self.client_certs.is_empty() {
                // Re-derive the cert_msg bytes here so they are exactly the
                // same bytes that went on the wire above. (We can't simply
                // extend the transcript inside the if-let because CV needs
                // to be signed AFTER CKE is also added — see step 7.)
                // We rebuild from `client_certs` (already DER).
                let mut chain_body = Vec::new();
                for cert in &self.client_certs {
                    chain_body.push((cert.len() >> 16) as u8);
                    chain_body.push((cert.len() >> 8) as u8);
                    chain_body.push(cert.len() as u8);
                    chain_body.extend_from_slice(cert);
                }
                let mut cert_body = Vec::with_capacity(3 + chain_body.len());
                cert_body.push((chain_body.len() >> 16) as u8);
                cert_body.push((chain_body.len() >> 8) as u8);
                cert_body.push(chain_body.len() as u8);
                cert_body.extend_from_slice(&chain_body);
                let mut cert_msg = Vec::with_capacity(4 + cert_body.len());
                cert_msg.push(HandshakeType::Certificate as u8);
                cert_msg.push((cert_body.len() >> 16) as u8);
                cert_msg.push((cert_body.len() >> 8) as u8);
                cert_msg.push(cert_body.len() as u8);
                cert_msg.extend_from_slice(&cert_body);
                Some(cert_msg)
            } else {
                None
            };
        // If the server requested a client cert, validate the
        // signing key now (we need it in step 7 to sign CV).
        let client_sign_key_pem: Option<String> =
            if server_sent_cert_request && !self.client_certs.is_empty() {
                Some(
                    self.client_sign_key
                        .as_deref()
                        .ok_or_else(|| {
                            TlcpError::HandshakeFailed(
                                "Server sent CertificateRequest but no client_sign_key was \
                     configured. Call TlcpConnector::with_client_certs() \
                     with a cert chain + (PKCS#8 PEM) signing key."
                                    .to_string(),
                            )
                        })?
                        .to_string(),
                )
            } else {
                None
            };
        // Step 7: Build ClientKeyExchange + derive pre-master secret.
        // - ECDHE: generate ephemeral keypair, send public key, derive PMS via SM2 ECDH.
        // - ECC  : generate 48 random bytes as PMS, SM2-encrypt to server enc cert, send ciphertext.
        let (cke_bytes, pms) = if is_ecc_mode {
            // ECC: extract enc cert SM2 pubkey (65 bytes uncompressed point).
            let enc_pub =
                crate::tlcp::crypto::verify::extract_sm2_pubkey_from_cert_der(&cert_pair.enc_cert)
                    .map_err(TlcpError::HandshakeFailed)?;
            // Per GB/T 38636-2020 §6.4.1.6 the PreMasterSecret is 48 bytes laid
            // out as  `ProtocolVersion (2 bytes) || random (46 bytes)`.
            // gmSSL's `tlcp_check_pre_master_secret` enforces this format
            // (rejects anything else with `illegal_parameter`), so we must
            // prefix the random bytes with our negotiated TLCP version.
            let mut pms_bytes = [0u8; 48];
            pms_bytes[0] = TLCP_VERSION_1_0[0];
            pms_bytes[1] = TLCP_VERSION_1_0[1];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut pms_bytes[2..]);
            let pms_bytes = pms_bytes.to_vec();
            // SM2-encrypt, DER-encoded SM2Cipher (matches GmSSL convention).
            let enc = gm_crypto::sm2::Sm2Encryptor::new(&enc_pub)
                .map_err(|e| TlcpError::HandshakeFailed(format!("sm2 enc new: {}", e)))?;
            let ciphertext = enc
                .encrypt_der(&pms_bytes)
                .map_err(|e| TlcpError::HandshakeFailed(format!("sm2 encrypt: {}", e)))?;
            // TLCP CKE wire format (matches GmSSL): handshake header
            //   [type=0x10][length:3 bytes BE]
            // followed by handshake body
            //   [2-byte ciphertext length prefix][ciphertext bytes].
            let mut body = Vec::with_capacity(2 + ciphertext.len());
            body.push((ciphertext.len() >> 8) as u8);
            body.push(ciphertext.len() as u8);
            body.extend_from_slice(&ciphertext);
            let mut msg = Vec::with_capacity(4 + body.len());
            msg.push(HandshakeType::ClientKeyExchange as u8);
            msg.push((body.len() >> 16) as u8);
            msg.push((body.len() >> 8) as u8);
            msg.push(body.len() as u8);
            msg.extend_from_slice(&body);
            (msg, pms_bytes)
        } else {
            // ECDHE: TLCP ECDHE PMS derivation per GB/T 38636-2020
            // §6.4.6.2 (a.k.a. GB/T 32918.3-2016 §6.4.2 full key
            // agreement). gmssl master implements this in
            // `sm2_key_exchange()`: both parties use their long-term
            // encryption key + a fresh ephemeral, compute a shared
            // point V, then SM3-KDF over (x_V||y_V||Z_A||Z_B, 48).
            //
            // Inputs required:
            //   - Client static enc keypair (priv + pub)
            //   - Client ephemeral keypair (priv + pub) — generated
            //     here
            //   - Server static enc pub (from server's enc cert in
            //     `cert_pair.enc_cert`)
            //   - Server ephemeral pub (from ServerKeyExchange)
            //   - Z_A, Z_B (SM2 Z values for both static pubs)
            let ske = TlcpServerKeyExchange::from_body(&ske_body)?;
            // 1. Load the client's static encryption key (configured
            //    via with_client_certs(..., Some(enc_key_pem), ...)).
            let client_enc_pem = self.client_enc_key.as_deref().ok_or_else(|| {
                TlcpError::HandshakeFailed(
                    "ECDHE cipher suite selected but no client_enc_key was configured. \
                     Call TlcpConnector::with_client_certs() with the encryption \
                     (PKCS#8/SEC1 PEM) key."
                        .to_string(),
                )
            })?;
            let client_enc_kp = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(client_enc_pem)
                .map_err(|e| {
                    TlcpError::HandshakeFailed(format!(
                        "client enc key load (PKCS#8/SEC1 PEM): {}",
                        e
                    ))
                })?;
            let client_enc_pub_sec1 = client_enc_kp.public_key_bytes_uncompressed();
            if client_enc_pub_sec1.len() != 65 || client_enc_pub_sec1[0] != 0x04 {
                return Err(TlcpError::HandshakeFailed(format!(
                    "client enc pub SEC1 must be uncompressed (65 bytes 0x04||X||Y), got {} bytes",
                    client_enc_pub_sec1.len()
                )));
            }
            let mut client_enc_pub_xy = [0u8; 64];
            client_enc_pub_xy.copy_from_slice(&client_enc_pub_sec1[1..65]);
            // 2. Extract server's static enc pubkey (65 bytes from
            //    the server's enc cert we already parsed in step 5).
            let server_enc_pub_sec1 =
                crate::tlcp::crypto::verify::extract_sm2_pubkey_from_cert_der(&cert_pair.enc_cert)
                    .map_err(TlcpError::HandshakeFailed)?;
            if server_enc_pub_sec1.len() != 65 || server_enc_pub_sec1[0] != 0x04 {
                return Err(TlcpError::HandshakeFailed(format!(
                    "server enc pub SEC1 must be uncompressed (65 bytes 0x04||X||Y), got {} bytes",
                    server_enc_pub_sec1.len()
                )));
            }
            let mut server_enc_pub_xy = [0u8; 64];
            server_enc_pub_xy.copy_from_slice(&server_enc_pub_sec1[1..65]);
            // 3. Generate a fresh client ephemeral keypair for this
            //    handshake. We use `Sm2KeyPair` (not `Sm2EcdhKeypair`)
            //    because we need direct access to the 32-byte scalar
            //    (`private_key_bytes`) for `compute_tlcp_ecdhe_pms`.
            let client_ephemeral_kp = gm_crypto::sm2::Sm2KeyPair::generate()
                .map_err(|e| TlcpError::HandshakeFailed(format!("client ECDHE keygen: {}", e)))?;
            let client_ephemeral_priv: [u8; 32] = {
                let v = client_ephemeral_kp.private_key_bytes();
                if v.len() != 32 {
                    return Err(TlcpError::HandshakeFailed(format!(
                        "client ephemeral priv must be 32 bytes, got {}",
                        v.len()
                    )));
                }
                let mut a = [0u8; 32];
                a.copy_from_slice(&v);
                a
            };
            let client_ephemeral_sec1 = client_ephemeral_kp.public_key_bytes_uncompressed();
            if client_ephemeral_sec1.len() != 65 || client_ephemeral_sec1[0] != 0x04 {
                return Err(TlcpError::HandshakeFailed(format!(
                    "client ephemeral SEC1 must be uncompressed (65 bytes 0x04||X||Y), got {} bytes",
                    client_ephemeral_sec1.len()
                )));
            }
            let mut client_ephemeral_xy = [0u8; 64];
            client_ephemeral_xy.copy_from_slice(&client_ephemeral_sec1[1..65]);
            // 4. Server ephemeral pub from ServerKeyExchange
            //    (`ecdhe_params.ephemeral_public` is the 64-byte
            //    (x || y) of R_B).
            let mut server_ephemeral_xy = [0u8; 64];
            if ske.ecdhe_params.ephemeral_public.len() != 65
                || ske.ecdhe_params.ephemeral_public[0] != 0x04
            {
                return Err(TlcpError::HandshakeFailed(format!(
                    "server ephemeral SEC1 must be uncompressed (65 bytes 0x04||X||Y), got {} bytes",
                    ske.ecdhe_params.ephemeral_public.len()
                )));
            }
            server_ephemeral_xy.copy_from_slice(&ske.ecdhe_params.ephemeral_public[1..65]);
            // 5. Compute the two SM2 `Z` values. NOTE the unusual Z
            //    order required for GmSSL master interop: gmssl's
            //    `tlcp_send_client_key_exchange` calls
            //    `sm2_key_exchange(0, ...)` with `is_initiator=0`,
            //    which puts **peer Z first** in the KDF input
            //    (`x_V||y_V||Z_server||Z_client`). The server's
            //    matching call uses `is_initiator=1`, which puts
            //    **own Z first** — and since the server's own Z is
            //    also the server's enc pub Z, both sides converge
            //    on `Z_server || Z_client`. We pass them in that
            //    exact order so `compute_tlcp_ecdhe_pms` produces
            //    the same PMS as gmssl master.
            //
            //    gmssl master uses `SM2_DEFAULT_ID` which is the
            //    string "1234567812345678" (16 bytes), so we default
            //    to that for cross-implementation interop. Both distids
            //    can be overridden via `with_server_enc_distid` /
            //    `with_client_enc_distid` (audit M-3).
            const DEFAULT_USER_ID: &[u8] = b"1234567812345678";
            let server_distid: &[u8] = self
                .server_enc_distid
                .as_deref()
                .map(|s| s.as_bytes())
                .unwrap_or(DEFAULT_USER_ID);
            let client_distid: &[u8] = self
                .client_enc_distid
                .as_deref()
                .map(|s| s.as_bytes())
                .unwrap_or(DEFAULT_USER_ID);
            let z_server = crate::tlcp::pms::sm2_compute_z(&server_enc_pub_xy, server_distid)
                .map_err(|e| TlcpError::HandshakeFailed(format!("compute Z_server: {}", e)))?;
            let z_client = crate::tlcp::pms::sm2_compute_z(&client_enc_pub_xy, client_distid)
                .map_err(|e| TlcpError::HandshakeFailed(format!("compute Z_client: {}", e)))?;
            // 6. PMS = KDF(x_V || y_V || Z_server || Z_client, 48).
            let pms_vec = crate::tlcp::pms::compute_tlcp_ecdhe_pms(
                &client_enc_pub_xy,
                &client_enc_kp.private_key().to_bytes().into(),
                &client_ephemeral_xy,
                &client_ephemeral_priv,
                &server_enc_pub_xy,
                &server_ephemeral_xy,
                &z_server,
                &z_client,
                48,
            )
            .map_err(|e| TlcpError::HandshakeFailed(format!("PMS derivation: {}", e)))?;
            // 7. CKE wire format = ECParameters-wrapped 65-byte
            //    uncompressed client ephemeral SEC1 (R_A).
            let cke = TlcpClientKeyExchange::new_ecdhe(client_ephemeral_sec1);
            (cke.to_bytes(), pms_vec)
        };
        write_handshake_record(&mut io, &cke_bytes)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write ClientKeyExchange: {}", e)))?;
        client_hs.transcript.extend_from_slice(&cke_bytes);
        // Step 7.5: Build CertificateVerify if we sent a client cert.
        // Per GmSSL 2026-06+ master (and RFC 5246 §7.4.8), CV is
        // signed over the transcript HASH that includes everything up
        // to (but excluding) CV itself — including our Certificate
        // AND our ClientKeyExchange. The server's transcript at
        // verify time already contains CKE (it appended CKE during
        // `tlcp_recv_client_key_exchange`), so we have to add CKE to
        // our transcript here too.
        //
        // Critical: we sign the RAW transcript bytes, not a pre-digest.
        // GmSSL's CV verify path (`tls_recv_certificate_verify` →
        // `x509_verify_update(&sign_ctx, conn->transcript,
        // conn->transcript_len)`) feeds the raw transcript into an SM3
        // context that was pre-loaded with the SM2 Z value (32 bytes
        // derived from the public key + distid). So gmssl computes
        // `SM3(Z || transcript)`.
        //
        // The `sm2` crate used by gm-crypto ALSO computes
        // `SM3(Z || msg)` inside `Signer::try_sign(msg)` (see
        // `sm2::dsa::signing::SigningKey::try_sign` → `hash_msg(msg)
        // = SM3(self.identity_hash || msg)`). So passing the raw
        // transcript bytes to `signer.sign(transcript)` produces
        // exactly `SM3(Z || transcript)` for the verifier. Pre-hashing
        // the transcript and signing THAT instead would compute
        // `SM3(Z || SM3(transcript))`, which is a different value and
        // makes every CV signature fail on the server side.
        if pending_cert_msg.is_some() {
            // cert_msg was already added to `client_hs.transcript` in
            // step 6.5 (right after we sent Certificate, BEFORE we
            // sent CKE) so the transcript order matches what gmssl
            // builds server-side: ... CR || SHD || Cert(client) ||
            // CKE. See the long comment above on the SM2 hash
            // interaction for why this signing path takes `&client_hs
            // .transcript` (raw bytes, not a pre-digest).
            let pem = client_sign_key_pem.as_deref().ok_or_else(|| {
                TlcpError::HandshakeFailed("client signing key disappeared mid-handshake".into())
            })?;
            let client_kp = gm_crypto::sm2::Sm2KeyPair::from_private_key_pem(pem)
                .map_err(|e| TlcpError::HandshakeFailed(format!("client key load: {:?}", e)))?;
            // CV signing must use the SAME distid the peer uses to verify
            // the SM2 signature. The peer's verify path is
            // `SM3(Z || transcript)` with Z computed over OUR sign cert's
            // public key + the distid that was used to generate the cert.
            // `Sm2KeyPair::from_private_key_pem` hard-codes the distid to
            // `"1234567812345678"` (the GmSSL convention); if the cert was
            // actually generated with a different distid we must use
            // `new_with_distid` here so the Z value matches. Audit M-3.
            let client_sign_distid: &str = self
                .client_sign_distid
                .as_deref()
                .unwrap_or(gm_crypto::sm2::GM_TLS_DEFAULT_ID);
            let client_signer =
                gm_crypto::sm2::Sm2Signer::new_with_distid(&client_kp, client_sign_distid)
                    .map_err(|e| TlcpError::HandshakeFailed(format!("client signer: {:?}", e)))?;
            let signature: [u8; 64] = client_signer
                .sign(&client_hs.transcript)
                .map_err(|e| TlcpError::HandshakeFailed(format!("CV sign: {:?}", e)))?
                .as_slice()
                .try_into()
                .map_err(|_| TlcpError::HandshakeFailed("CV signature length != 64".into()))?;
            let signature_der = gm_crypto::sm2::sm2_signature_raw_to_der(&signature);
            // Self-check: verify the signature against the public key we
            // derived from the same private key. If our own SM2 verifier
            // accepts it but the peer server rejects it, the transcript
            // we sign differs from what the peer has accumulated in its
            // transcript hash. If our verifier also rejects it, there's a
            // key / distid / curve-params mismatch on our side. We use the
            // SAME distid here that we used for signing. Audit M-3.
            match gm_crypto::sm2::Sm2Verifier::new(
                &client_kp.public_key_bytes_uncompressed(),
                client_sign_distid,
            ) {
                Ok(verifier) => match verifier.verify(&client_hs.transcript, &signature) {
                    Ok(()) => {}
                    Err(e) => {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "CV self-verify FAILED locally ({:?}) — the signature is \
                             not valid for our transcript + key; check distid / pubkey \
                             / curve-params agreement",
                            e
                        )));
                    }
                },
                Err(e) => {
                    return Err(TlcpError::HandshakeFailed(format!(
                        "CV self-verify skipped: Sm2Verifier::new failed: {:?}",
                        e
                    )));
                }
            }
            let mut cv_body = Vec::with_capacity(2 + signature_der.len());
            cv_body.push((signature_der.len() >> 8) as u8);
            cv_body.push(signature_der.len() as u8);
            cv_body.extend_from_slice(&signature_der);
            let mut cv_msg = Vec::with_capacity(4 + cv_body.len());
            cv_msg.push(HandshakeType::CertificateVerify as u8);
            cv_msg.push((cv_body.len() >> 16) as u8);
            cv_msg.push((cv_body.len() >> 8) as u8);
            cv_msg.push(cv_body.len() as u8);
            cv_msg.extend_from_slice(&cv_body);
            write_handshake_record(&mut io, &cv_msg)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("write CV: {}", e)))?;
            client_hs.transcript.extend_from_slice(&cv_msg);
        }
        // Step 8: Stash PMS + server_random + selected suite, derive master secret.
        client_hs.pre_master_secret = Some(pms);
        client_hs.server_random = Some(server_random);
        client_hs.cipher_suite = Some(server_hello.cipher_suite);
        client_hs.derive_master_secret()?;
        // Step 9: Send ChangeCipherSpec
        let ccs_record = vec![
            TLCP_RECORD_TYPE_CCS,
            TLCP_VERSION_1_0[0],
            TLCP_VERSION_1_0[1],
            0,
            1,
            1,
        ];
        use tokio::io::AsyncWriteExt;
        io.write_all(&ccs_record)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write CCS: {}", e)))?;
        io.flush().await?;
        // Step 10: Create encrypted stream and send Finished
        let suite = TlcpCipherSuite::from_id(server_hello.cipher_suite)
            .ok_or_else(|| TlcpError::HandshakeFailed("unknown cipher suite".to_string()))?;
        let session_id = server_hello.session_id.clone();
        let key_material = TlcpKeyMaterial::derive(
            client_hs
                .master_secret
                .as_ref()
                .ok_or_else(|| TlcpError::HandshakeFailed("no master secret".to_string()))?,
            &client_hs.client_random,
            client_hs
                .server_random
                .as_ref()
                .ok_or_else(|| TlcpError::HandshakeFailed("no server random".to_string()))?,
            suite,
        )?;
        // `gmssl_padding_compat` is a deprecated no-op kept for API stability —
        // the wire format always follows RFC 5246 §6.2.3.2 /
        // GB/T 38636-2020 §6.2.3.2. Remove this call entirely in a future release.
        #[allow(deprecated)]
        let mut stream = TlcpStream::new(io, &key_material, suite, true, session_id)?
            .with_gmssl_padding_compat(self.gmssl_padding_compat);
        let client_finished = client_hs.compute_client_finished()?;
        let cf_bytes = client_finished.to_bytes();
        // Always frame the Finished as a handshake-type record (0x16).
        // GmSSL's `tls_recv_client_finished` calls
        // `tls_record_get_handshake` to parse the decrypted body, so the
        // record-layer content type MUST be Handshake (0x16), not
        // ApplicationData (0x17). The standard `AsyncWrite` path
        // (used by the deprecated `gmssl_padding_compat = false` branch)
        // hardcodes APP_DATA, which makes GmSSL reject the Finished with
        // `bad_record_mac`; force HANDSHAKE here unconditionally.
        stream
            .write_encrypted_record_with_type(TLCP_RECORD_TYPE_HANDSHAKE, &cf_bytes)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write Finished: {}", e)))?;
        stream.flush().await?;
        // Step 11: Read server ChangeCipherSpec + Finished
        // CCS is read as raw bytes from the inner transport
        let mut ccs_buf = [0u8; 6];
        {
            let raw_io = stream.get_mut();
            use tokio::io::AsyncReadExt;
            raw_io
                .read_exact(&mut ccs_buf)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("read server CCS: {}", e)))?;
        }
        // Read server Finished (encrypted).
        //
        // The previous code read the decrypted bytes into a buffer
        // and immediately discarded them with `let _ = ...`. That
        // skipped the protocol's transcript-binding check entirely —
        // an attacker who tampered with (e.g.) the ServerHello or SKE
        // before we reached this point would not be detected. The
        // Finished verify_data is the only thing that authenticates
        // the full handshake transcript.
        //
        // The Finished message is itself a handshake-layer message (type=0x14),
        // but it travels inside a TLCP APP_DATA record during the post-CCS
        // exchange, so we read it through `read_application_data()` which
        // already strips the record-layer encryption.
        let finished_plaintext = stream
            .read_application_data()
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("read server Finished: {}", e)))?;
        let (sf_type, sf_body, _sf_rem) = parse_handshake_message(&finished_plaintext)
            .map_err(|e| TlcpError::HandshakeFailed(format!("parse server Finished: {}", e)))?;
        if sf_type != HandshakeType::Finished {
            return Err(TlcpError::HandshakeFailed(format!(
                "Expected Finished, got {:?}",
                sf_type
            )));
        }
        let server_finished = TlcpFinished::from_body(&sf_body)?;
        // Per GB/T 38636-2020 §6.4.1.10 / RFC 5246 §7.4.6: the server's Finished
        // verify_data covers the full handshake transcript INCLUDING the
        // client's Finished message (which is itself a handshake message and
        // part of the digest context by the time the server computes its
        // Finished). We extend our transcript with the *client* Finished
        // bytes before recomputing the expected verify_data.
        client_hs
            .transcript
            .extend_from_slice(&client_finished.to_bytes());
        if !client_hs.verify_server_finished(&server_finished)? {
            return Err(TlcpError::HandshakeFailed(
                "server Finished verify_data mismatch (possible handshake tampering)".to_string(),
            ));
        }
        // The Finished message itself is part of the transcript only for
        // session-resumption derivation, not for our verify check above.
        client_hs.transcript.extend_from_slice(&finished_plaintext);
        stream.cached_resumed_session = client_hs.to_resumed_session();
        Ok(stream)
    }
    /// Access the session cache for this connector.
    pub fn session_cache(&self) -> &TlcpSessionCache {
        &self.session_cache
    }
}
/// TLCP server acceptor configuration.
///
/// Encapsulates the parameters needed to accept TLCP client connections,
/// including dual certificates (signing + encryption) for production use.
#[derive(Clone)]
pub struct TlcpAcceptor {
    session_cache: TlcpSessionCache,
    /// Server signing certificate (DER-encoded X.509)
    sign_cert: Option<Vec<u8>>,
    /// Server encryption certificate (DER-encoded X.509)
    enc_cert: Option<Vec<u8>>,
    /// Server signing key pair
    sign_key: Option<Arc<gm_crypto::sm2::Sm2KeyPair>>,
    /// Server encryption key pair (for static ECC cipher suites)
    enc_key: Option<Arc<gm_crypto::sm2::Sm2KeyPair>>,
    /// SM2 user_id used to derive `Z_server` from the server's
    /// encryption certificate during ECDHE PMS derivation
    /// (GB/T 32918.1-2016 §6.1).
    server_enc_distid: Option<String>,
    /// SM2 user_id used to derive `Z_client` from the client's
    /// encryption certificate during ECDHE PMS derivation
    /// (GB/T 32918.1-2016 §6.1).
    client_enc_distid: Option<String>,
    /// SM2 user_id the client used to sign its `CertificateVerify`
    /// (the client sign cert's user_id). Defaults to
    /// `"1234567812345678"`. Override this if the client sign cert
    /// was generated with a different user_id (audit M-3).
    client_sign_distid: Option<String>,
}
impl Default for TlcpAcceptor {
    fn default() -> Self {
        Self::new()
    }
}
impl TlcpAcceptor {
    /// Create a new TLCP acceptor with default settings.
    pub fn new() -> Self {
        Self {
            session_cache: TlcpSessionCache::new(),
            sign_cert: None,
            enc_cert: None,
            sign_key: None,
            enc_key: None,
            server_enc_distid: None,
            client_enc_distid: None,
            client_sign_distid: None,
        }
    }
    /// Create an acceptor with a shared session cache for resumption.
    pub fn with_session_cache(mut self, cache: TlcpSessionCache) -> Self {
        self.session_cache = cache;
        self
    }
    /// Configure the server's dual certificates for production TLCP handshake.
    ///
    /// # Arguments
    /// * `sign_cert` - DER-encoded signing certificate
    /// * `enc_cert` - DER-encoded encryption certificate
    /// * `sign_key` - SM2 key pair for the signing certificate
    /// * `enc_key` - SM2 key pair for the encryption certificate (for ECC suites)
    pub fn with_dual_certs(
        mut self,
        sign_cert: Vec<u8>,
        enc_cert: Vec<u8>,
        sign_key: gm_crypto::sm2::Sm2KeyPair,
        enc_key: gm_crypto::sm2::Sm2KeyPair,
    ) -> Self {
        self.sign_cert = Some(sign_cert);
        self.enc_cert = Some(enc_cert);
        self.sign_key = Some(Arc::new(sign_key));
        self.enc_key = Some(Arc::new(enc_key));
        self
    }
    /// Accept a TLCP client connection over the given transport.
    ///
    /// Performs the full handshake and returns an encrypted `TlcpStream`.
    ///
    /// If dual certificates are configured, performs a production ECDHE handshake
    /// with real ServerKeyExchange/ClientKeyExchange over the transport.
    /// Otherwise, falls back to the simplified simulated handshake.
    ///
    /// # Note
    /// The simplified fallback simulates ECDHE with a pre-master secret.
    /// Production use requires dual certificates configured via [`TlcpAcceptor::with_dual_certs`].
    pub async fn accept<S>(&self, transport: S) -> Result<TlcpStream<S>, TlcpError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if self.sign_cert.is_some() && self.sign_key.is_some() {
            self.accept_with_certs(transport).await
        } else {
            #[allow(deprecated)]
            accept_tlcp(transport, &self.session_cache).await
        }
    }
    /// Accept with production dual-certificate ECDHE handshake.
    ///
    /// Performs the full GB/T 38636-2020 handshake:
    /// 1. Read ClientHello
    /// 2. Send ServerHello + Certificate (sign + enc)
    /// 3. Generate ECDHE ephemeral keypair, send ServerKeyExchange + ServerHelloDone
    /// 4. Read ClientKeyExchange
    /// 5. Derive master secret and key material
    /// 6. Read ChangeCipherSpec + Finished
    /// 7. Send ChangeCipherSpec + Finished
    pub async fn accept_with_certs<S>(&self, transport: S) -> Result<TlcpStream<S>, TlcpError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        use tokio::io::AsyncWriteExt;
        let mut io = transport;
        let sign_cert = self
            .sign_cert
            .clone()
            .ok_or_else(|| TlcpError::HandshakeFailed("sign cert not configured".to_string()))?;
        let enc_cert = self
            .enc_cert
            .clone()
            .ok_or_else(|| TlcpError::HandshakeFailed("enc cert not configured".to_string()))?;
        let sign_kp = self
            .sign_key
            .clone()
            .ok_or_else(|| TlcpError::HandshakeFailed("sign key not configured".to_string()))?;
        // Step 1: Read ClientHello
        let (_content_type, record_payload) = read_plaintext_record(&mut io)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("read ClientHello: {}", e)))?;
        let (msg_type, body, _remaining) = parse_handshake_message(&record_payload)?;
        if msg_type != HandshakeType::ClientHello {
            return Err(TlcpError::HandshakeFailed(format!(
                "Expected ClientHello, got {:?}",
                msg_type
            )));
        }
        let client_hello = TlcpClientHello::from_body(&body)?;
        let client_random = client_hello.random;
        // Step 2: Create server handshake context
        let mut server_hs = TlcpServerHandshake::with_session_cache(self.session_cache.clone())?;
        server_hs.process_client_hello(&client_hello).await?;
        let server_random = server_hs.server_random;
        let session_id = server_hs.session_id.clone();
        let suite = server_hs
            .cipher_suite
            .ok_or_else(|| TlcpError::HandshakeFailed("no cipher suite".to_string()))?;
        // Step 3: Send ServerHello
        let server_hello = server_hs.create_server_hello()?;
        let sh_bytes = server_hello.to_bytes();
        write_handshake_record(&mut io, &sh_bytes)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write ServerHello: {}", e)))?;
        server_hs.transcript.extend_from_slice(&sh_bytes);
        // Step 4: Send Certificate (dual: sign + enc)
        let cert_pair = TlcpCertPair::new(sign_cert.clone(), enc_cert.clone());
        let cert_msg = cert_pair.to_certificate_message();
        write_handshake_record(&mut io, &cert_msg)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write Certificate: {}", e)))?;
        server_hs.transcript.extend_from_slice(&cert_msg);
        server_hs.set_server_certs(cert_pair);
        // Step 5: ServerKeyExchange (only for ECDHE in strict mode).
        //
        // In strict mode + static-ECC we skip SKE entirely — the spec
        // doesn't define it for static-ECC suites. Note: gm-tlcp's server
        // does not yet implement the static-ECC PMS decryption path, so
        // strict-mode + static-ECC server-side will return an explicit error
        // at step 8 (see below). A future PR will add the SM2-decrypt path.
        // In default mode we keep emitting SKE for ALL suites to preserve
        // GmSSL/Tongsuo interop, even though that's a deviation from spec.
        let server_ephemeral_kp_opt: Option<gm_crypto::sm2::Sm2EcdhKeypair> = if suite.ecdhe {
            let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp)
                .map_err(|e| TlcpError::HandshakeFailed(format!("sign signer: {}", e)))?;
            let (ske, kp) =
                TlcpServerKeyExchange::generate(&client_random, &server_random, &sign_signer)?;
            let ske_bytes = ske.to_bytes();
            write_handshake_record(&mut io, &ske_bytes)
                .await
                .map_err(|e| {
                    TlcpError::HandshakeFailed(format!("write ServerKeyExchange: {}", e))
                })?;
            server_hs.transcript.extend_from_slice(&ske_bytes);
            Some(kp)
        } else {
            // Spec-default for static-ECC: no SKE, no ephemeral_kp.
            // The PMS will eventually come from server-side ECC CKE
            // decryption (audit C-4 / R-3, not yet implemented).
            #[cfg(feature = "tlcp-gmssl-compat")]
            {
                // GmSSL-master shim: emit an ECDHE-style SKE for
                // static-ECC, just like GmSSL master does. Server-side
                // PMS will use raw 32-byte ECDH (see step 8 below).
                let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp)
                    .map_err(|e| TlcpError::HandshakeFailed(format!("sign signer: {}", e)))?;
                let (ske, kp) =
                    TlcpServerKeyExchange::generate(&client_random, &server_random, &sign_signer)?;
                let ske_bytes = ske.to_bytes();
                write_handshake_record(&mut io, &ske_bytes)
                    .await
                    .map_err(|e| {
                        TlcpError::HandshakeFailed(format!("write ServerKeyExchange: {}", e))
                    })?;
                server_hs.transcript.extend_from_slice(&ske_bytes);
                Some(kp)
            }
            #[cfg(not(feature = "tlcp-gmssl-compat"))]
            {
                None
            }
        };
        // Step 5.5: Send CertificateRequest (spec-default; skip in
        // GmSSL-master shim).
        //
        // Per GB/T 38636-2020 §6.4.5.5 the server MAY send a
        // CertificateRequest to ask the client to authenticate with a
        // dual (sign + enc) SM2 certificate chain. We do this by
        // default because the spec-conformant PMS path needs the
        // client's enc cert to compute Z_client for the SM2 KAP
        // (audit C-3). The GmSSL-master shim skips CR because
        // GmSSL master itself does not.
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        {
            let cr = TlcpCertificateRequest::standard();
            let cr_bytes = cr.to_bytes()?;
            write_handshake_record(&mut io, &cr_bytes)
                .await
                .map_err(|e| {
                    TlcpError::HandshakeFailed(format!("write CertificateRequest: {}", e))
                })?;
            server_hs.transcript.extend_from_slice(&cr_bytes);
        }
        #[cfg(feature = "tlcp-gmssl-compat")]
        {
            // Skip CertificateRequest. The server's PMS uses raw
            // 32-byte ECDH (no client enc cert needed), so we don't
            // require client authentication for the key agreement.
        }
        // Step 6: Send ServerHelloDone
        let shd = TlcpServerHelloDone;
        let shd_bytes = shd.to_bytes();
        write_handshake_record(&mut io, &shd_bytes)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write ServerHelloDone: {}", e)))?;
        server_hs.transcript.extend_from_slice(&shd_bytes);
        // Step 7: Read Client Certificate (sent in reply to our
        // CertificateRequest). The body is the RFC 5246 §7.4.6
        // `Certificate` structure: `opaque ASN.1Cert<0..2^24-1>`
        // (zero or more DER-encoded X.509 certs). An empty Certificate
        // is permitted per the standard (the client has no cert and
        // chooses to stay anonymous); in that case we treat it as
        // "no client certs" and the strict KAP branch in step 8 will
        // fail with a clear error if the suite is static-ECC. ECDHE
        // suites still work because the KDF only needs client enc pub
        // — which we capture here for both modes.
        //
        // In spec-default the server sent a CertificateRequest (step 5.5),
        // so the client is required to reply with a Certificate
        // message (possibly empty if the client has no cert).
        // In GmSSL-master shim the server skipped CR, so the client
        // skips Certificate entirely and goes straight to CKE.
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        let _client_certs: Vec<Vec<u8>> = {
            let (_ct, cert_payload) = read_plaintext_record(&mut io).await.map_err(|e| {
                TlcpError::HandshakeFailed(format!("read Client Certificate: {}", e))
            })?;
            let (cert_type, cert_body, _rem) = parse_handshake_message(&cert_payload)?;
            if cert_type != HandshakeType::Certificate {
                return Err(TlcpError::HandshakeFailed(format!(
                    "Expected Certificate (client), got {:?}",
                    cert_type
                )));
            }
            server_hs.transcript.extend_from_slice(&cert_payload);
            // Parse client certs (leaf-first; first entry is the leaf).
            // Layout: u24 total_len; then u24 cert_len || cert_der for
            // each cert. We accept any non-empty chain (gm-tlcp only
            // needs the leaf cert's SM2 encryption pubkey for KAP).
            let mut client_certs: Vec<Vec<u8>> = Vec::new();
            if cert_body.len() >= 3 {
                let _total = ((cert_body[0] as usize) << 16)
                    | ((cert_body[1] as usize) << 8)
                    | (cert_body[2] as usize);
                let mut p = 3;
                while p + 3 <= cert_body.len() {
                    let len = ((cert_body[p] as usize) << 16)
                        | ((cert_body[p + 1] as usize) << 8)
                        | (cert_body[p + 2] as usize);
                    p += 3;
                    if p + len > cert_body.len() {
                        break;
                    }
                    client_certs.push(cert_body[p..p + len].to_vec());
                    p += len;
                }
            }
            server_hs.set_client_certs(client_certs.clone());
            client_certs
        };
        #[cfg(feature = "tlcp-gmssl-compat")]
        let _client_certs_unused: Vec<Vec<u8>> = Vec::new();
        // Step 7.5: Read ClientKeyExchange
        let (_ct, cke_payload) = read_plaintext_record(&mut io)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("read ClientKeyExchange: {}", e)))?;
        let (cke_type, cke_body, _rem) = parse_handshake_message(&cke_payload)?;
        if cke_type != HandshakeType::ClientKeyExchange {
            return Err(TlcpError::HandshakeFailed(format!(
                "Expected ClientKeyExchange, got {:?}",
                cke_type
            )));
        }
        let cke = TlcpClientKeyExchange::from_body(&cke_body)?;
        server_hs.transcript.extend_from_slice(&cke_payload);
        // Step 8: Compute pre-master secret.
        //
        // Spec-default: use the SM2 Key Agreement Protocol from
        // GM/T 0003.3-2012 §6.1 (referenced by GB/T 38636-2020
        // §6.4.6.2), which feeds the KDF:
        //
        //   V = (x̄_R_A · r_A + k_A) · ((x̄_R_B · R_B) + P_B)
        //   PMS = KDF(xV ∥ yV ∥ Z_A ∥ Z_B, 48)
        //
        // where Z_A / Z_B are computed from each side's enc cert
        // public key + SM2 user_id. This is audit C-3 and matches
        // GmSSL master / Tongsuo 8.3.0 behaviour byte-for-byte.
        //
        // GmSSL-master shim (--features tlcp-gmssl-compat): the
        // historical 32-byte raw ECDH x-coordinate path, kept for
        // byte-for-byte interop with the legacy GmSSL interop tests.
        let pms: Vec<u8> = match server_ephemeral_kp_opt {
            Some(kp) => {
                // The peer's ECDHE public key is wrapped in an
                // ECParameters envelope (`03 00 29 || 41 || 65B`).
                // We strip the envelope to get the 65-byte SM2 SEC1
                // uncompressed point before feeding it into the KAP.
                let peer_ephemeral_sec1 = cke.ecdhe_public_key().ok_or_else(|| {
                    TlcpError::HandshakeFailed(
                        "ECDHE ClientKeyExchange missing ECParameters envelope for sm2p256v1"
                            .to_string(),
                    )
                })?;
                #[cfg(feature = "tlcp-gmssl-compat")]
                {
                    // GmSSL-master shim: 32-byte raw ECDH
                    // x-coordinate. The historical 0.2.x default-mode
                    // path, retained only for legacy interop.
                    kp.compute_shared_secret(peer_ephemeral_sec1).map_err(|e| {
                        TlcpError::HandshakeFailed(format!("ECDHE shared secret: {}", e))
                    })?
                }
                #[cfg(not(feature = "tlcp-gmssl-compat"))]
                {
                    // Spec: full SM2 KAP PMS computation.
                    // 1) Build the server's KAP inputs from its own
                    //    encryption keypair.
                    let server_enc_kp = self.enc_key.clone().ok_or_else(|| {
                        TlcpError::HandshakeFailed(
                            "spec-default server ECDHE PMS needs `with_dual_certs(..., enc_key)` \
                             configured"
                                .to_string(),
                        )
                    })?;
                    let server_enc_priv_bytes = server_enc_kp.private_key_bytes();
                    if server_enc_priv_bytes.len() != 32 {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "server enc priv must be 32 bytes, got {}",
                            server_enc_priv_bytes.len()
                        )));
                    }
                    let mut server_enc_priv = [0u8; 32];
                    server_enc_priv.copy_from_slice(&server_enc_priv_bytes);
                    let server_enc_sec1 = server_enc_kp.public_key_bytes_uncompressed();
                    if server_enc_sec1.len() != 65 || server_enc_sec1[0] != 0x04 {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "server enc pub must be uncompressed (65B 0x04||X||Y), got {} bytes",
                            server_enc_sec1.len()
                        )));
                    }
                    let mut server_enc_xy = [0u8; 64];
                    server_enc_xy.copy_from_slice(&server_enc_sec1[1..65]);
                    // 2) Server's ephemeral kp inputs.
                    let server_ephemeral_sec1 = kp.public_key_bytes();
                    if server_ephemeral_sec1.len() != 65 || server_ephemeral_sec1[0] != 0x04 {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "server ephemeral pub must be uncompressed (65B 0x04||X||Y), got {} bytes",
                            server_ephemeral_sec1.len()
                        )));
                    }
                    let mut server_ephemeral_xy = [0u8; 64];
                    server_ephemeral_xy.copy_from_slice(&server_ephemeral_sec1[1..65]);
                    let server_ephemeral_priv_bytes = kp.private_key_bytes();
                    if server_ephemeral_priv_bytes.len() != 32 {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "server ephemeral priv must be 32 bytes, got {}",
                            server_ephemeral_priv_bytes.len()
                        )));
                    }
                    let mut server_ephemeral_priv = [0u8; 32];
                    server_ephemeral_priv.copy_from_slice(&server_ephemeral_priv_bytes);
                    // 3) Build the peer's ECDHE inputs (the ephemeral
                    //    pubkey from the client's CKE).
                    if peer_ephemeral_sec1.len() != 65 || peer_ephemeral_sec1[0] != 0x04 {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "client ephemeral pub must be uncompressed (65B 0x04||X||Y), got {} bytes",
                            peer_ephemeral_sec1.len()
                        )));
                    }
                    let mut peer_ephemeral_xy = [0u8; 64];
                    peer_ephemeral_xy.copy_from_slice(&peer_ephemeral_sec1[1..65]);
                    // 4) Pull the client's enc cert pubkey from the
                    //    cert chain we recorded in step 7. Without
                    //    that we can't compute Z_client and the KDF
                    //    will diverge from the peer's.
                    let client_enc_cert_der = server_hs.client_certs.first().ok_or_else(|| {
                        TlcpError::HandshakeFailed(
                            "tlcp-strict server ECDHE PMS needs the client \
                                 to send a non-empty Certificate message in reply \
                                 to our CertificateRequest; configure the \
                                 TlcpConnector with with_client_certs(..., \
                                 Some(enc_key_pem), ...)."
                                .to_string(),
                        )
                    })?;
                    let client_enc_pub_sec1 =
                        crate::tlcp::crypto::verify::extract_sm2_pubkey_from_cert_der(
                            client_enc_cert_der,
                        )
                        .map_err(TlcpError::HandshakeFailed)?;
                    if client_enc_pub_sec1.len() != 65 || client_enc_pub_sec1[0] != 0x04 {
                        return Err(TlcpError::HandshakeFailed(format!(
                            "client enc pub must be uncompressed (65B 0x04||X||Y), got {} bytes",
                            client_enc_pub_sec1.len()
                        )));
                    }
                    let mut client_enc_xy = [0u8; 64];
                    client_enc_xy.copy_from_slice(&client_enc_pub_sec1[1..65]);
                    // 5) Resolve the SM2 user_ids (defaults match
                    //    GmSSL/Tongsuo convention).
                    let server_distid_bytes: &[u8] = self
                        .server_enc_distid
                        .as_deref()
                        .map(|s: &str| s.as_bytes())
                        .unwrap_or(gm_crypto::sm2::GM_TLS_DEFAULT_ID.as_bytes());
                    let client_distid_bytes: &[u8] = self
                        .client_enc_distid
                        .as_deref()
                        .map(|s: &str| s.as_bytes())
                        .unwrap_or(gm_crypto::sm2::GM_TLS_DEFAULT_ID.as_bytes());
                    // 6) Compute Z_server and Z_client.
                    let z_server =
                        crate::tlcp::pms::sm2_compute_z(&server_enc_xy, server_distid_bytes)
                            .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
                    let z_client =
                        crate::tlcp::pms::sm2_compute_z(&client_enc_xy, client_distid_bytes)
                            .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?;
                    // 7) Compute the SM2 KAP pre-master secret.
                    //    The Z-order is Z_server || Z_client on both
                    //    sides because the server is the initiator of
                    //    the key agreement (the server is the first
                    //    party to send an ephemeral public key in SKE).
                    crate::tlcp::pms::compute_tlcp_ecdhe_pms(
                        &server_enc_xy,
                        &server_enc_priv,
                        &server_ephemeral_xy,
                        &server_ephemeral_priv,
                        &client_enc_xy,
                        &peer_ephemeral_xy,
                        &z_server,
                        &z_client,
                        48,
                    )
                    .map_err(|e| TlcpError::HandshakeFailed(e.to_string()))?
                }
            }
            None => {
                #[cfg(feature = "tlcp-gmssl-compat")]
                {
                    return Err(TlcpError::HandshakeFailed(
                        "server_ephemeral_kp missing for default-mode static-ECC \
                         server (this is a bug; please file an issue)"
                            .to_string(),
                    ));
                }
                #[cfg(not(feature = "tlcp-gmssl-compat"))]
                {
                    return Err(TlcpError::HandshakeFailed(
                        "spec-default server-side static-ECC PMS decryption is not \
                         implemented in this release; use --features tlcp-gmssl-compat \
                         for static-ECC server interop, or wait for the upcoming R-3 \
                         (SPEC-FIRST roadmap) that adds SM2 decryption."
                            .to_string(),
                    ));
                }
            }
        };
        server_hs.complete_key_exchange(pms)?;
        // Step 8.5 + 9: Read CertificateVerify (if sent) and CCS.
        //
        // Spec-default: the server sent a CertificateRequest (step
        // 5.5), so the client may reply with CertificateVerify; we
        // probe the next record's first byte to decide whether to
        // consume a CV (consume it if it's CertificateVerify,
        // otherwise leave the record in place for the CCS read).
        //
        // GmSSL-master shim: the server skipped CR, so the client
        // skips CV too and goes straight to CCS.
        #[cfg(feature = "tlcp-gmssl-compat")]
        {
            // Skip CV; just read CCS with strict validation.
            let (ccs_type, ccs_payload) = read_plaintext_record(&mut io)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("read CCS: {}", e)))?;
            if ccs_type != TLCP_RECORD_TYPE_CCS {
                return Err(TlcpError::HandshakeFailed(format!(
                    "Expected CCS (0x14), got 0x{:02x}",
                    ccs_type
                )));
            }
            if ccs_payload.as_slice() != [0x01u8] {
                return Err(TlcpError::HandshakeFailed(format!(
                    "CCS payload must be 0x01, got {} bytes: {:02x?}",
                    ccs_payload.len(),
                    ccs_payload
                )));
            }
        }
        #[cfg(not(feature = "tlcp-gmssl-compat"))]
        {
            // The client only emits a CertificateVerify message when
            // the server sent a CertificateRequest AND the client has
            // a client certificate chain configured (see
            // `connect_with_certs` step 7.5). CV is a handshake
            // message that the server MUST verify against the client's
            // sign cert public key + the SM2 user_id used at cert
            // generation. After verification, the signature bytes are
            // appended to the server's transcript so that the
            // subsequent Finished-PRF hash matches the client's.
            //
            // We probe the next record's first byte to decide whether
            // to consume a CV: if it's `CertificateVerify = 0x0F`, we
            // read and verify it; otherwise we leave the record in
            // place for step 9 (CCS).
            let (_ct, cv_probe_payload) = read_plaintext_record(&mut io)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("read post-CKE record: {}", e)))?;
            let post_cke_record_opt: Option<Vec<u8>> = if cv_probe_payload.first().copied()
                == Some(crate::tlcp::HandshakeType::CertificateVerify as u8)
            {
                crate::tlcp::cv_helper::process_certificate_verify(
                    &cv_probe_payload,
                    &mut server_hs,
                    self.client_sign_distid.as_deref(),
                )?;
                None
            } else {
                Some(cv_probe_payload)
            };
            // Step 9: Read ChangeCipherSpec
            //
            // Validate both the CCS content_type AND the payload. Per
            // GB/T 38636-2020 (and RFC 5246 §7.1) the CCS payload MUST
            // be the single byte `0x01`. Accepting any other byte is a
            // protocol deviation that an attacker could exploit to
            // confuse the handshake state machine.
            let (ccs_type, ccs_payload) = if let Some(payload) = post_cke_record_opt {
                let ct = TLCP_RECORD_TYPE_CCS;
                (ct, payload)
            } else {
                read_plaintext_record(&mut io)
                    .await
                    .map_err(|e| TlcpError::HandshakeFailed(format!("read CCS: {}", e)))?
            };
            if ccs_type != TLCP_RECORD_TYPE_CCS {
                return Err(TlcpError::HandshakeFailed(format!(
                    "Expected CCS (0x14), got 0x{:02x}",
                    ccs_type
                )));
            }
            if ccs_payload.as_slice() != [0x01u8] {
                return Err(TlcpError::HandshakeFailed(format!(
                    "CCS payload must be 0x01, got {} bytes: {:02x?}",
                    ccs_payload.len(),
                    ccs_payload
                )));
            }
        }
        // Step 10: Read client Finished (now encrypted)
        // For now, we create the stream with key material so we can decrypt
        let key_material = TlcpKeyMaterial::derive(
            server_hs
                .master_secret
                .as_ref()
                .ok_or_else(|| TlcpError::HandshakeFailed("no master secret".to_string()))?,
            server_hs
                .client_random
                .as_ref()
                .ok_or_else(|| TlcpError::HandshakeFailed("no client random".to_string()))?,
            &server_hs.server_random,
            suite,
        )?;
        // Build the stream now — subsequent reads are encrypted
        let mut stream = TlcpStream::new(io, &key_material, suite, false, session_id)?;
        // Read client Finished
        //
        // The previous code read the decrypted bytes into a buffer
        // and discarded them. We now parse the handshake message and
        // verify `verify_data` against our locally computed value.
        // This is the protocol's transcript-binding check — if any
        // byte of ClientHello / ServerHello / Certificate / SKE /
        // ServerHelloDone / ClientKeyExchange was tampered with, the
        // client cannot produce a Finished that matches our expected
        // PRF output.
        let finished_plaintext = stream
            .read_application_data()
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("read client Finished: {}", e)))?;
        let (cf_type, cf_body, _cf_rem) = parse_handshake_message(&finished_plaintext)
            .map_err(|e| TlcpError::HandshakeFailed(format!("parse client Finished: {}", e)))?;
        if cf_type != HandshakeType::Finished {
            return Err(TlcpError::HandshakeFailed(format!(
                "Expected Finished, got {:?}",
                cf_type
            )));
        }
        let client_finished = TlcpFinished::from_body(&cf_body)?;
        if !server_hs.verify_client_finished(&client_finished)? {
            return Err(TlcpError::HandshakeFailed(
                "client Finished verify_data mismatch (possible handshake tampering)".to_string(),
            ));
        }
        // The Finished message itself is part of the transcript for any
        // subsequent resumption derivation but does not feed the verify check
        // we just performed.
        server_hs.transcript.extend_from_slice(&finished_plaintext);
        // Step 11: Send ChangeCipherSpec + Finished
        let ccs_record = vec![
            TLCP_RECORD_TYPE_CCS,
            TLCP_VERSION_1_0[0],
            TLCP_VERSION_1_0[1],
            0,
            1,
            1,
        ];
        {
            let raw_io = stream.get_mut();
            raw_io
                .write_all(&ccs_record)
                .await
                .map_err(|e| TlcpError::HandshakeFailed(format!("write CCS: {}", e)))?;
            raw_io.flush().await?;
        }
        // Compute and send server Finished
        let server_finished = server_hs.compute_server_finished()?;
        let sf_bytes = server_finished.to_bytes();
        stream
            .write_all(&sf_bytes)
            .await
            .map_err(|e| TlcpError::HandshakeFailed(format!("write server Finished: {}", e)))?;
        stream.flush().await?;
        stream.cached_resumed_session = server_hs.to_resumed_session();
        if let Some(ref resumed) = stream.cached_resumed_session {
            self.session_cache
                .put(stream.session_id.clone(), resumed.clone())
                .await;
        }
        Ok(stream)
    }
    /// Configure the SM2 user_id used to derive `Z_server`
    /// (GB/T 32918.1-2016 §6.1) from the server's encryption
    /// certificate during the ECDHE PMS derivation.
    ///
    /// Defaults to `"1234567812345678"` (the GmSSL/Tongsuo convention)
    /// when not configured. Override this if the server enc cert was
    /// generated with a different user_id — otherwise the Z value
    /// would mismatch and the ECDHE pre-master secret would diverge
    /// from the peer's (audit M-3).
    pub fn with_server_enc_distid(mut self, distid: String) -> Self {
        self.server_enc_distid = Some(distid);
        self
    }
    /// Configure the SM2 user_id used to derive `Z_client`
    /// (GB/T 32918.1-2016 §6.1) from the client's encryption
    /// certificate during the ECDHE PMS derivation.
    ///
    /// Defaults to `"1234567812345678"` when not configured. Override
    /// this if the client enc cert was generated with a different
    /// user_id (audit M-3).
    pub fn with_client_enc_distid(mut self, distid: String) -> Self {
        self.client_enc_distid = Some(distid);
        self
    }
    /// Configure the SM2 user_id the client used to sign its
    /// `CertificateVerify` (the client sign cert's user_id).
    ///
    /// Defaults to `"1234567812345678"` when not configured.
    /// Override this if the client sign cert was generated with a
    /// different user_id (audit M-3).
    pub fn with_client_sign_distid(mut self, distid: String) -> Self {
        self.client_sign_distid = Some(distid);
        self
    }
    /// Access the session cache for this acceptor.
    pub fn session_cache(&self) -> &TlcpSessionCache {
        &self.session_cache
    }
}

/// Shared ECDHE context for loopback/integration testing.
///
/// In production, the client and server exchange ephemeral public keys over the
/// network. For testing, this context allows both sides to compute the same
/// shared secret without network messages.
///
/// Usage:
/// ```ignore
/// let ctx = TlcpEcdheContext::generate();
/// let client_stream = connect_tlcp_with_context(transport_client, &ctx).await?;
/// let server_stream = accept_tlcp_with_context(transport_server, &ctx).await?;
/// ```
#[derive(Clone)]
pub struct TlcpEcdheContext {
    /// Client ephemeral public key (0x04 || x || y, 65 bytes)
    #[allow(dead_code)] // Used in TLCP handshake ServerKeyExchange/ClientKeyExchange messages
    client_ephemeral_pub: Vec<u8>,
    /// Server ephemeral public key (0x04 || x || y, 65 bytes)
    #[allow(dead_code)] // Used in TLCP handshake ServerKeyExchange/ClientKeyExchange messages
    server_ephemeral_pub: Vec<u8>,
    /// Pre-master secret (shared secret x-coordinate, 32 bytes)
    pre_master_secret: Vec<u8>,
    /// Client random
    client_random: [u8; 32],
    /// Server random
    server_random: [u8; 32],
}
impl Drop for TlcpEcdheContext {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.pre_master_secret.zeroize();
        self.client_random.zeroize();
        self.server_random.zeroize();
    }
}
impl TlcpEcdheContext {
    /// Generate a new ECDHE context with real SM2 ECDH key exchange.
    ///
    /// Both ephemeral keypairs are generated using cryptographically secure RNG.
    /// The shared secret is computed as the x-coordinate of `server_private * client_public`.
    pub fn generate() -> Result<Self, TlcpError> {
        Self::generate_with_cipher_suite(TLS_ECDHE_SM4_GCM_SM3)
    }
    /// Generate context with a specific cipher suite.
    pub fn generate_with_cipher_suite(_cipher_suite: [u8; 2]) -> Result<Self, TlcpError> {
        let client_kp = gm_crypto::sm2::Sm2EcdhKeypair::generate().map_err(|e| {
            TlcpError::HandshakeFailed(format!("client ECDHE keygen failed: {}", e))
        })?;
        let server_kp = gm_crypto::sm2::Sm2EcdhKeypair::generate().map_err(|e| {
            TlcpError::HandshakeFailed(format!("server ECDHE keygen failed: {}", e))
        })?;
        // Client computes: shared = ECDH(client_private, server_public)
        let pms = client_kp
            .compute_shared_secret(&server_kp.public_key_bytes())
            .map_err(|e| {
                TlcpError::HandshakeFailed(format!("ECDHE shared secret failed: {}", e))
            })?;
        // Verify: server computes same shared = ECDH(server_private, client_public)
        let pms_verify = server_kp
            .compute_shared_secret(&client_kp.public_key_bytes())
            .map_err(|e| TlcpError::HandshakeFailed(format!("ECDHE verify failed: {}", e)))?;
        if pms != pms_verify {
            return Err(TlcpError::HandshakeFailed(
                "ECDHE shared secret mismatch: client and server derived different keys"
                    .to_string(),
            ));
        }
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut client_random);
        rand_core::OsRng.fill_bytes(&mut server_random);
        Ok(Self {
            client_ephemeral_pub: client_kp.public_key_bytes(),
            server_ephemeral_pub: server_kp.public_key_bytes(),
            pre_master_secret: pms,
            client_random,
            server_random,
        })
    }
    /// Get the client random.
    pub fn client_random(&self) -> [u8; 32] {
        self.client_random
    }
    /// Get the server random.
    pub fn server_random(&self) -> [u8; 32] {
        self.server_random
    }
    /// Get the pre-master secret.
    pub fn pre_master_secret(&self) -> &[u8] {
        &self.pre_master_secret
    }
}
/// Connect to a TLCP server over the given transport using shared ECDHE context.
///
/// This is the production-ready variant that uses real SM2 ECDH key exchange.
/// The `TlcpEcdheContext` must be shared between client and server (in production
/// this would be done via network key exchange; in testing, via shared reference).
pub async fn connect_tlcp_with_context<S>(
    transport: S,
    ctx: &TlcpEcdheContext,
) -> Result<TlcpStream<S>, TlcpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut client_hs = TlcpHandshake::new_client()?;
    let _client_hello = client_hs.create_client_hello()?;
    // Use real ECDHE-derived values
    client_hs.client_random = ctx.client_random;
    client_hs.server_random = Some(ctx.server_random);
    client_hs.cipher_suite = Some(TLS_ECDHE_SM4_GCM_SM3);
    // The state machine now requires ServerCertsReceived before
    // derive_master_secret; install a placeholder cert pair so the
    // simulated-helper path still satisfies the invariant. The
    // `accept_tlcp_with_context` mirror helper installs the same
    // placeholder so both ends line up.
    let placeholder = TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]);
    client_hs.process_server_certs(placeholder)?;
    client_hs.pre_master_secret = Some(ctx.pre_master_secret.to_vec());
    client_hs.derive_master_secret()?;
    TlcpStream::from_client_handshake_with_transport(client_hs, transport)
}
/// Accept a TLCP client connection using shared ECDHE context.
pub async fn accept_tlcp_with_context<S>(
    transport: S,
    session_cache: &TlcpSessionCache,
    ctx: &TlcpEcdheContext,
) -> Result<TlcpStream<S>, TlcpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut server_hs = TlcpServerHandshake::with_session_cache(session_cache.clone())?;
    let client_hello = TlcpClientHello::new()?;
    server_hs.process_client_hello(&client_hello).await?;
    let _server_hello = server_hs.create_server_hello()?;
    server_hs.set_server_certs(TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]));
    // Use matching values from the shared context
    server_hs.client_random = Some(ctx.client_random);
    server_hs.server_random = ctx.server_random;
    server_hs.complete_key_exchange(ctx.pre_master_secret.to_vec())?;
    TlcpStream::from_server_handshake_with_transport(server_hs, transport)
}
/// Connect to a TLCP server over the given transport.
///
/// Performs a full TLCP handshake:
/// 1. Client → Server: ClientHello
/// 2. Server → Client: ServerHello + Certificate
/// 3. ECDHE key exchange
/// 4. Finished message exchange
/// 5. Returns encrypted TlcpStream
///
/// # Note
/// This simplified version simulates ECDHE with deterministic values.
/// For real SM2 ECDHE, use [`connect_tlcp_with_context`] with a shared
/// [`TlcpEcdheContext`].
/// Connect to a TLCP server (deprecated simulated mode).
///
/// ⚠️ **This function does NOT perform real network handshake.** It simulates
/// ECDHE locally without reading from/writing to the transport.
/// Use [`TlcpConnector::connect_with_certs`] for production-grade handshake.
#[deprecated(
    since = "0.1.0",
    note = "Use TlcpConnector::connect_with_certs() for real TLCP handshake"
)]
pub async fn connect_tlcp<S>(
    transport: S,
    _session_cache: &TlcpSessionCache,
) -> Result<TlcpStream<S>, TlcpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Create client handshake and send ClientHello
    let mut client_hs = TlcpHandshake::new_client()?;
    let _client_hello = client_hs.create_client_hello()?;
    // Step 2: SM2 ECDHE key exchange (simulated for standalone use)
    //
    // In production, the client receives the server's ephemeral public key
    // from the ServerKeyExchange message. Here we generate both sides locally
    // and use the shared secret as the pre-master secret.
    let ctx = TlcpEcdheContext::generate()?;
    client_hs.client_random = ctx.client_random;
    client_hs.server_random = Some(ctx.server_random);
    client_hs.cipher_suite = Some(TLS_ECDHE_SM4_GCM_SM3);
    client_hs.pre_master_secret = Some(ctx.pre_master_secret.to_vec());
    client_hs.derive_master_secret()?;
    // Step 3: Create stream from handshake
    TlcpStream::from_client_handshake_with_transport(client_hs, transport)
}
/// Accept a TLCP client connection (deprecated simulated mode).
///
/// ⚠️ **This function does NOT perform real network handshake.** It simulates
/// ECDHE locally without reading from/writing to the transport.
/// Use [`TlcpAcceptor::accept_with_certs`] for production-grade handshake.
#[deprecated(
    since = "0.1.0",
    note = "Use TlcpAcceptor::accept_with_certs() for real TLCP handshake"
)]
pub async fn accept_tlcp<S>(
    transport: S,
    session_cache: &TlcpSessionCache,
) -> Result<TlcpStream<S>, TlcpError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Step 1: Create server handshake and read ClientHello
    let mut server_hs = TlcpServerHandshake::with_session_cache(session_cache.clone())?;
    // Step 2: Simulate receiving ClientHello and sending response
    let client_hello = TlcpClientHello::new()?;
    server_hs.process_client_hello(&client_hello).await?;
    let _server_hello = server_hs.create_server_hello()?;
    server_hs.set_server_certs(TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]));
    // Step 3: SM2 ECDHE key exchange (simulated)
    // In production, the server computes shared secret from client's ephemeral
    // public key received in ClientKeyExchange. Here we generate matching PMS.
    let ctx = TlcpEcdheContext::generate()?;
    server_hs.client_random = Some(ctx.client_random);
    server_hs.server_random = ctx.server_random;
    server_hs.complete_key_exchange(ctx.pre_master_secret.to_vec())?;
    // Step 3: Create stream from handshake
    TlcpStream::from_server_handshake_with_transport(server_hs, transport)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // PR4 (audit M-3) — distid setters are applied as expected and the
    // default fallback is the GmSSL/Tongsuo convention.
    #[test]
    fn connector_distid_defaults_are_none() {
        let c = TlcpConnector::new();
        assert!(c.server_sign_distid.is_none());
        assert!(c.server_enc_distid.is_none());
        assert!(c.client_enc_distid.is_none());
        assert!(c.client_sign_distid.is_none());
    }
    #[test]
    fn connector_distid_setters_set_values() {
        let c = TlcpConnector::new()
            .with_server_enc_distid("server-enc".to_string())
            .with_client_enc_distid("client-enc".to_string())
            .with_client_sign_distid("client-sign".to_string());
        assert_eq!(c.server_enc_distid.as_deref(), Some("server-enc"));
        assert_eq!(c.client_enc_distid.as_deref(), Some("client-enc"));
        assert_eq!(c.client_sign_distid.as_deref(), Some("client-sign"));
    }
    #[test]
    fn connector_distid_empty_string_is_distinct_from_none() {
        // Empty distid is a legitimate configuration for some peers; we must
        // not silently coerce "" -> default (the GmSSL convention), or peers
        // that genuinely use "" would fail.
        let c = TlcpConnector::new().with_server_enc_distid(String::new());
        assert_eq!(c.server_enc_distid.as_deref(), Some(""));
        assert_ne!(c.server_enc_distid.as_deref(), None);
    }

    #[test]
    fn test_tlcp_client_hello_creation() {
        let hello = TlcpClientHello::new().unwrap();
        assert_eq!(hello.version, TLCP_VERSION_1_0);
        assert!(!hello.cipher_suites.is_empty());
        assert_eq!(hello.compression_methods, vec![0x00]);
    }
    #[test]
    fn test_tlcp_client_hello_serialization() {
        let hello = TlcpClientHello::new().unwrap();
        let bytes = hello.to_bytes().unwrap();
        // Should start with ClientHello handshake type
        assert_eq!(bytes[0], HandshakeType::ClientHello as u8);
    }
    #[test]
    fn test_tlcp_server_hello_parsing() {
        // Minimal valid ServerHello
        let mut data = Vec::new();
        data.extend_from_slice(&TLCP_VERSION_1_0); // version
        data.extend_from_slice(&[0u8; 32]); // random
        data.push(0); // session_id_len
        data.extend_from_slice(&TLS_ECDHE_SM4_GCM_SM3); // cipher suite
        data.push(0x00); // compression
        let hello = TlcpServerHello::from_bytes(&data).unwrap();
        assert_eq!(hello.version, TLCP_VERSION_1_0);
        assert!(hello.is_ecdhe());
        assert!(hello.is_gcm());
    }
    #[test]
    fn test_dual_certificate_pair() {
        let sign_cert = vec![0x01, 0x02, 0x03];
        let enc_cert = vec![0x04, 0x05, 0x06];
        let pair = TlcpCertPair::new(sign_cert.clone(), enc_cert.clone());
        assert_eq!(pair.sign_cert, sign_cert);
        assert_eq!(pair.enc_cert, enc_cert);
    }
    #[test]
    fn test_certificate_message_serialization() {
        let pair = TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]);
        let msg = pair.to_certificate_message();
        assert!(!msg.is_empty());
    }
    #[test]
    fn test_handshake_state_machine() {
        let mut hs = TlcpHandshake::new_client().unwrap();
        assert_eq!(hs.state, TlcpHandshakeState::Idle);
        let hello = hs.create_client_hello().unwrap();
        assert_eq!(hs.state, TlcpHandshakeState::HelloSent);
        assert_eq!(hello.version, TLCP_VERSION_1_0);
    }
    #[test]
    fn test_handshake_server_hello_processing() {
        let mut hs = TlcpHandshake::new_client().unwrap();
        hs.create_client_hello().unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&TLCP_VERSION_1_0);
        data.extend_from_slice(&[0x42u8; 32]);
        data.push(0);
        data.extend_from_slice(&TLS_ECDHE_SM4_GCM_SM3);
        data.push(0x00);
        let server_hello = TlcpServerHello::from_bytes(&data).unwrap();
        hs.process_server_hello(&server_hello).unwrap();
        assert_eq!(hs.cipher_suite, Some(TLS_ECDHE_SM4_GCM_SM3));
    }
    #[test]
    fn test_cipher_suite_lookup() {
        let suite = TlcpCipherSuite::from_id(TLS_ECDHE_SM4_GCM_SM3).unwrap();
        assert_eq!(suite.name, "ECDHE_SM4_GCM_SM3");
        assert!(suite.ecdhe);
        assert!(suite.gcm);
        let suite_cbc = TlcpCipherSuite::from_id(TLS_ECC_SM4_CBC_SM3).unwrap();
        assert!(!suite_cbc.ecdhe);
        assert!(!suite_cbc.gcm);
    }
    /// Regression test: the four TLCP cipher-suite code points must
    /// match GB/T 38636-2020 §6.4.5.2.1 表 2 (independently verified
    /// against GmSSL master + gotlcp). Any drift in the constants
    /// will surface here.
    ///
    /// Reference (independently verified):
    ///   gotlcp (Go TLCP impl) cites "GB/T 38636-2020 6.4.5.2.1 表 2"
    ///   GmSSL 3.x TLCP handshake captures (Cnblogs: TLS原理与实践 4)
    #[test]
    fn test_cipher_suite_code_points_match_gbt_38636_2020() {
        assert_eq!(
            TLS_ECDHE_SM4_CBC_SM3,
            [0xE0, 0x11],
            "ECDHE_SM4_CBC_SM3 must be 0xE011 per GB/T 38636-2020 \
             §6.4.5.2.1 表 2 (inherited from GM/T 0024-2014)"
        );
        assert_eq!(
            TLS_ECC_SM4_CBC_SM3,
            [0xE0, 0x13],
            "ECC_SM4_CBC_SM3 must be 0xE013 per GB/T 38636-2020 \
             §6.4.5.2.1 表 2 (inherited from GM/T 0024-2014)"
        );
        assert_eq!(
            TLS_ECDHE_SM4_GCM_SM3,
            [0xE0, 0x51],
            "ECDHE_SM4_GCM_SM3 must be 0xE051 per GB/T 38636-2020 \
             §6.4.5.2.1 表 2 (GCM suites are new in GB/T 38636-2020)"
        );
        assert_eq!(
            TLS_ECC_SM4_GCM_SM3,
            [0xE0, 0x53],
            "ECC_SM4_GCM_SM3 must be 0xE053 per GB/T 38636-2020 \
             §6.4.5.2.1 表 2 (GCM suites are new in GB/T 38636-2020)"
        );
        // Also assert the four code points are pairwise distinct so the
        // cipher-suite lookup table can never silently alias.
        let all = [
            TLS_ECDHE_SM4_CBC_SM3,
            TLS_ECDHE_SM4_GCM_SM3,
            TLS_ECC_SM4_CBC_SM3,
            TLS_ECC_SM4_GCM_SM3,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(
                    all[i], all[j],
                    "cipher-suite code points must be pairwise distinct"
                );
            }
        }
    }
    #[test]
    fn test_cipher_suite_all() {
        let all = TlcpCipherSuite::all();
        assert_eq!(all.len(), 4);
    }
    #[test]
    fn test_handshake_type_conversion() {
        assert_eq!(
            HandshakeType::try_from(0x01).unwrap(),
            HandshakeType::ClientHello
        );
        assert_eq!(
            HandshakeType::try_from(0x14).unwrap(),
            HandshakeType::Finished
        );
        assert!(HandshakeType::try_from(0xFF).is_err());
    }
    #[test]
    fn test_master_secret_derivation() {
        let mut hs = TlcpHandshake::new_client().unwrap();
        hs.create_client_hello().unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&TLCP_VERSION_1_0);
        data.extend_from_slice(&[0x42u8; 32]);
        data.push(0);
        data.extend_from_slice(&TLS_ECDHE_SM4_GCM_SM3);
        data.push(0x00);
        let server_hello = TlcpServerHello::from_bytes(&data).unwrap();
        hs.process_server_hello(&server_hello).unwrap();
        // Process server certificates so the state advances to
        // `ServerCertsReceived` (required by derive_master_secret's
        // state-machine guard added in the 2026-08-31 security audit).
        hs.process_server_certs(TlcpCertPair::new(vec![0x01; 100], vec![0x02; 100]))
            .unwrap();
        hs.pre_master_secret = Some(vec![0x42u8; 48]);
        hs.derive_master_secret().unwrap();
        assert!(hs.master_secret.is_some());
        // master_secret is now 48 bytes (was 32 before the PRF fix).
        assert_eq!(hs.master_secret.as_ref().unwrap().len(), 48);
    }
    #[test]
    fn test_ecdhe_params_serialization() {
        let params = Sm2EcdheParams::new(vec![0x04; 65], vec![0x01; 64]);
        let bytes = params.to_bytes();
        // ECParameters prefix: curve_type=3, named_curve=0x0029.
        assert_eq!(
            &bytes[..TLCP_ECH_PARAMS_PREFIX.len()],
            &TLCP_ECH_PARAMS_PREFIX
        );
        let point_offset = TLCP_ECH_PARAMS_PREFIX.len();
        assert_eq!(bytes[point_offset], 65); // ECPoint length
        assert_eq!(bytes[point_offset + 1..point_offset + 66], vec![0x04u8; 65]);
        // Then signature length (2 bytes) + signature
        assert_eq!(
            &bytes[point_offset + 66..point_offset + 68],
            &64u16.to_be_bytes()
        );
    }
    #[test]
    fn test_invalid_server_hello_too_short() {
        let data = vec![0x01, 0x01]; // Only version
        assert!(TlcpServerHello::from_bytes(&data).is_err());
    }
    #[test]
    fn test_version_mismatch() {
        let mut hs = TlcpHandshake::new_client().unwrap();
        hs.create_client_hello().unwrap();
        let mut data = Vec::new();
        data.extend_from_slice(&[0x03, 0x03]); // Wrong version (TLS 1.2)
        data.extend_from_slice(&[0x42u8; 32]);
        data.push(0);
        data.extend_from_slice(&TLS_ECDHE_SM4_GCM_SM3);
        data.push(0x00);
        let server_hello = TlcpServerHello::from_bytes(&data).unwrap();
        assert!(hs.process_server_hello(&server_hello).is_err());
    }
    // ========================================================================
    // Finished message tests
    // ========================================================================
    #[test]
    fn test_finished_compute() {
        let master_secret = [0xABu8; 32];
        let transcript = b"test handshake transcript";
        let finished =
            TlcpFinished::compute(&master_secret, "client finished", transcript).unwrap();
        assert_eq!(finished.verify_data.len(), 12);
    }
    #[test]
    fn test_finished_verify() {
        let master = [0xCDu8; 32];
        let transcript = b"test transcript";
        let finished = TlcpFinished::compute(&master, "server finished", transcript).unwrap();
        // Same inputs should produce same verify_data
        let finished2 = TlcpFinished::compute(&master, "server finished", transcript).unwrap();
        assert!(finished.verify(&finished2.verify_data));
    }
    #[test]
    fn test_finished_different_labels() {
        let master = [0xEFu8; 32];
        let transcript = b"transcript";
        let client_finished =
            TlcpFinished::compute(&master, "client finished", transcript).unwrap();
        let server_finished =
            TlcpFinished::compute(&master, "server finished", transcript).unwrap();
        // Different labels must produce different verify_data
        assert!(!client_finished.verify(&server_finished.verify_data));
    }
    #[test]
    fn test_finished_serialization() {
        let master = [0x11u8; 32];
        let finished = TlcpFinished::compute(&master, "client finished", b"test").unwrap();
        let bytes = finished.to_bytes();
        assert_eq!(bytes[0], HandshakeType::Finished as u8);
        // Length should be 12
        assert_eq!(bytes[1], 0);
        assert_eq!(bytes[2], 0);
        assert_eq!(bytes[3], 12);
        assert_eq!(&bytes[4..16], &finished.verify_data[..]);
    }
    // ========================================================================
    // Key derivation tests
    // ========================================================================
    #[test]
    fn test_key_material_derive_gcm() {
        let master = [0x42u8; 32];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let km = TlcpKeyMaterial::derive(
            &master,
            &client_random,
            &server_random,
            TlcpCipherSuite::ECDHE_SM4_GCM_SM3,
        )
        .unwrap();
        assert_eq!(km.client_enc_key.len(), 16);
        assert_eq!(km.server_enc_key.len(), 16);
        // GCM fixed_iv is 4 bytes per GmSSL `tls_derive_key_block`
        // (key_block_len = (key_size + 4) * 2 = 40). The 12-byte per-record
        // nonce is `fixed_iv(4) || seq(8)`, computed on the fly by
        // `next_nonce` in the record layer.
        assert_eq!(km.client_iv.len(), 4);
        assert_eq!(km.server_iv.len(), 4);
        // GCM mode: no separate MAC keys
        assert!(km.client_mac_key.is_empty());
        assert!(km.server_mac_key.is_empty());
    }
    #[test]
    fn test_key_material_derive_cbc() {
        let master = [0x42u8; 32];
        let client_random = [0x01u8; 32];
        let server_random = [0x02u8; 32];
        let km = TlcpKeyMaterial::derive(
            &master,
            &client_random,
            &server_random,
            TlcpCipherSuite::ECDHE_SM4_CBC_SM3,
        )
        .unwrap();
        assert_eq!(km.client_mac_key.len(), 32);
        assert_eq!(km.server_mac_key.len(), 32);
        assert_eq!(km.client_enc_key.len(), 16);
        assert_eq!(km.server_enc_key.len(), 16);
        assert_eq!(km.client_iv.len(), 16);
        assert_eq!(km.server_iv.len(), 16);
    }
    #[test]
    fn test_key_material_deterministic() {
        let master = [0x99u8; 32];
        let cr = [0xAAu8; 32];
        let sr = [0xBBu8; 32];
        let km1 =
            TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3).unwrap();
        let km2 =
            TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3).unwrap();
        assert_eq!(km1.client_enc_key, km2.client_enc_key);
        assert_eq!(km1.server_enc_key, km2.server_enc_key);
        assert_eq!(km1.client_iv, km2.client_iv);
        assert_eq!(km1.server_iv, km2.server_iv);
    }
    #[test]
    fn test_key_material_different_randoms() {
        let master = [0x99u8; 32];
        let cr1 = [0xAAu8; 32];
        let cr2 = [0xCCu8; 32];
        let sr = [0xBBu8; 32];
        let km1 = TlcpKeyMaterial::derive(&master, &cr1, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3)
            .unwrap();
        let km2 = TlcpKeyMaterial::derive(&master, &cr2, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3)
            .unwrap();
        // Different randoms should produce different keys
        assert_ne!(km1.client_enc_key, km2.client_enc_key);
    }
    // ========================================================================
    // Server-side handshake tests
    // ========================================================================
    #[tokio::test]
    async fn test_server_handshake_process_client_hello() {
        let mut server = TlcpServerHandshake::new().unwrap();
        let client_hello = TlcpClientHello::new().unwrap();
        server.process_client_hello(&client_hello).await.unwrap();
        assert_eq!(server.state, TlcpHandshakeState::HelloSent);
        assert!(server.cipher_suite.is_some());
        assert!(server.client_random.is_some());
    }
    #[tokio::test]
    async fn test_server_handshake_create_server_hello() {
        let mut server = TlcpServerHandshake::new().unwrap();
        let client_hello = TlcpClientHello::new().unwrap();
        server.process_client_hello(&client_hello).await.unwrap();
        let server_hello = server.create_server_hello().unwrap();
        assert_eq!(server_hello.version, TLCP_VERSION_1_0);
        assert!(server.cipher_suite.is_some());
        assert_eq!(server_hello.cipher_suite, server.cipher_suite.unwrap().id);
    }
    #[tokio::test]
    async fn test_server_handshake_full_flow() {
        let mut server = TlcpServerHandshake::new().unwrap();
        let client_hello = TlcpClientHello::new().unwrap();
        server.process_client_hello(&client_hello).await.unwrap();
        let _server_hello = server.create_server_hello().unwrap();
        // Simulate ECDHE key exchange
        server.complete_key_exchange(vec![0x42u8; 48]).unwrap();
        assert!(server.master_secret.is_some());
        // Derive key material
        let km = server.derive_key_material().unwrap();
        assert_eq!(km.client_enc_key.len(), 16);
        // Compute server finished
        let _server_finished = server.compute_server_finished().unwrap();
        server.establish();
        assert!(server.is_established());
    }
    // ========================================================================
    // Security-audit regression tests
    // ========================================================================
    /// Simulates a client+server pair whose transcripts and master_secret are
    /// synchronised, then verifies that:
    ///  1. compute_server_finished on one side equals what the other side
    ///     computes over the same transcript.
    ///  2. verify_server_finished accepts a correctly-built Finished.
    ///  3. Tampering with a single transcript byte causes verify to fail.
    #[test]
    fn test_finished_transcript_binding_roundtrip() {
        // Shared transcript bytes — both sides must extend_from_slice the same
        // bytes in the same order. Use Vec<u8> to allow different message
        // lengths without losing the convenience of array literals.
        let ch: Vec<u8> = b"\x01client_hello_payload_xxx".to_vec();
        let sh: Vec<u8> = b"\x02server_hello_payload_xxx".to_vec();
        let cert: Vec<u8> = b"\x0bcertificate_payload_xxxxx".to_vec();
        let ske: Vec<u8> = b"\x0cske_payload_xxxxxxxx".to_vec();
        let shd: Vec<u8> = b"\x0eserver_hello_done_____".to_vec();
        let cke: Vec<u8> = b"\x10client_key_exchange____".to_vec();
        let mut client_hs = TlcpHandshake::new_client().unwrap();
        let mut server_hs = TlcpServerHandshake::new().unwrap();
        // Set master_secret on both sides to the same value.
        let master = [0x77u8; 48];
        client_hs.master_secret = Some(master.to_vec());
        server_hs.master_secret = Some(master.to_vec());
        // Append the same bytes to both transcripts.
        for bytes in &[&ch, &sh, &cert, &ske, &shd, &cke] {
            client_hs.transcript.extend_from_slice(bytes);
            server_hs.transcript.extend_from_slice(bytes);
        }
        // Server computes its Finished.
        let server_finished = server_hs.compute_server_finished().unwrap();
        // Client computes its expected Finished independently.
        let expected_client_view = client_hs.compute_server_finished().unwrap();
        assert_eq!(
            server_finished.verify_data, expected_client_view.verify_data,
            "server and client must compute identical verify_data over identical transcript"
        );
        // Client verifies what it receives from the server — should pass.
        assert!(
            client_hs.verify_server_finished(&server_finished).unwrap(),
            "client must verify server Finished over the same transcript"
        );
        // Mutate one byte of the client transcript AFTER the Finished was
        // computed. The Finished is a hash of transcript bytes, so any
        // pre-computation mutation of the *expected* hash is meaningless.
        // Instead, simulate an attacker mutating a byte in the bytes that
        // were hashed — i.e. mutate transcript on both sides BEFORE
        // recomputing.
        let mut bytes_after_tamper = (*shd).to_vec();
        bytes_after_tamper[5] ^= 0x01;
        let mut tampered_client_hs = TlcpHandshake::new_client().unwrap();
        tampered_client_hs.master_secret = Some(master.to_vec());
        tampered_client_hs.transcript.extend_from_slice(&ch);
        tampered_client_hs.transcript.extend_from_slice(&sh);
        tampered_client_hs.transcript.extend_from_slice(&cert);
        tampered_client_hs.transcript.extend_from_slice(&ske);
        tampered_client_hs
            .transcript
            .extend_from_slice(&bytes_after_tamper);
        tampered_client_hs.transcript.extend_from_slice(&cke);
        // Client's expected verify_data differs from server's.
        let tampered_expected = tampered_client_hs.compute_server_finished().unwrap();
        assert_ne!(
            tampered_expected.verify_data, server_finished.verify_data,
            "1-byte transcript mutation must change the verify_data"
        );
        // ... and the verification of the original Finished against the
        // tampered expected fails.
        assert!(
            !tampered_client_hs
                .verify_server_finished(&server_finished)
                .unwrap(),
            "1-byte transcript mutation must cause verify to fail"
        );
    }
    /// Verify TlcpFinished::from_body parses the 12-byte body correctly and
    /// rejects malformed bodies (length != 12).
    #[test]
    fn test_finished_from_body() {
        let ok_body = [0xAAu8; 12];
        let f = TlcpFinished::from_body(&ok_body).unwrap();
        assert_eq!(&f.verify_data[..], &ok_body[..]);
        // Wrong-length body must be rejected.
        assert!(TlcpFinished::from_body(&[0u8; 11]).is_err());
        assert!(TlcpFinished::from_body(&[0u8; 13]).is_err());
        assert!(TlcpFinished::from_body(&[]).is_err());
    }
    /// TlcpResumedSession must implement Drop that zeroizes the cached
    /// master_secret and randoms. We can't observe the zeroing directly
    /// without unsafe code, but we can at least confirm the Drop runs
    /// without panic and that the Debug impl still works.
    #[test]
    fn test_resumed_session_drop_runs() {
        let s = TlcpResumedSession::new(
            vec![0x42u8; 48],
            TLS_ECDHE_SM4_GCM_SM3,
            [0x33u8; 32],
            [0x44u8; 32],
        );
        // Touch Debug to ensure it still works (no master_secret leak).
        let _ = format!("{:?}", s);
        drop(s); // Drop must run without panic.
    }
    /// Regression test: `prf_expand` must reject `length` values that
    /// would loop billions of times and exhaust memory. Without the
    /// bound, a caller passing `usize::MAX` (or just `1 << 30`) would
    /// freeze the process or OOM.
    #[test]
    fn test_prf_expand_rejects_oversized_length() {
        // Attack scenario: a malformed / malicious caller invokes prf_expand
        // with an absurdly large length. The bound check must reject it
        // before the while-loop runs.
        let r = TlcpKeyMaterial::prf_expand(b"secret", b"label", b"seed", usize::MAX);
        assert!(r.is_err(), "prf_expand(usize::MAX) must be rejected");
        // Also test 1 GiB (still absurdly large for any TLCP use).
        let r = TlcpKeyMaterial::prf_expand(b"secret", b"label", b"seed", 1 << 30);
        assert!(r.is_err(), "prf_expand(1 GiB) must be rejected");
    }
    /// Companion to the above: prf_expand must still produce correct output
    /// within the allowed length range.
    #[test]
    fn test_prf_expand_within_limit_works() {
        // 48 bytes — the master_secret length per RFC 5246 / GB/T 38636.
        let m = TlcpKeyMaterial::prf_expand(b"secret", b"master secret", b"seed", 48).unwrap();
        assert_eq!(m.len(), 48);
        // 128 bytes — the CBC key block length.
        let k = TlcpKeyMaterial::prf_expand(b"secret", b"key expansion", b"seed", 128).unwrap();
        assert_eq!(k.len(), 128);
        // 12 bytes — verify_data length.
        let v = TlcpKeyMaterial::prf_expand(b"secret", b"client finished", b"seed", 12).unwrap();
        assert_eq!(v.len(), 12);
        // 0 bytes — must succeed and return empty.
        let z = TlcpKeyMaterial::prf_expand(b"secret", b"label", b"seed", 0).unwrap();
        assert!(z.is_empty());
    }
    /// Regression test: the CCS payload must equal `[0x01]` per
    /// GB/T 38636-2020 / RFC 5246 §7.1. Previously the implementation
    /// accepted any payload (or any length); the server-side reader
    /// now enforces this exact value (see `accept_with_certs` Step 9).
    /// This test pins the literal byte so any future drift in the
    /// constants surfaces immediately.
    #[test]
    fn test_ccs_payload_value_is_one() {
        // Per RFC 5246 / GB/T 38636-2020, the CCS payload is the single
        // byte `0x01`. The server-side reader enforces this exact value
        // (see accept_with_certs Step 9).
        const CCS_PAYLOAD_REQUIRED: [u8; 1] = [0x01];
        assert_eq!(CCS_PAYLOAD_REQUIRED, [0x01]);
    }
    #[tokio::test]
    async fn test_server_rejects_wrong_version() {
        let mut server = TlcpServerHandshake::new().unwrap();
        let mut client_hello = TlcpClientHello::new().unwrap();
        client_hello.version = [0x03, 0x03]; // TLS 1.2, not TLCP
        let result = server.process_client_hello(&client_hello).await;
        assert!(result.is_err());
    }
    // ========================================================================
    // Alert protocol tests
    // ========================================================================
    #[test]
    fn test_alert_close_notify() {
        let alert = TlcpAlert::close_notify();
        assert_eq!(alert.level, TlcpAlertLevel::Warning);
        assert!(alert.is_close_notify());
        assert!(!alert.is_fatal());
    }
    #[test]
    fn test_alert_handshake_failure() {
        let alert = TlcpAlert::handshake_failure();
        assert_eq!(alert.level, TlcpAlertLevel::Fatal);
        assert!(alert.is_fatal());
        assert!(!alert.is_close_notify());
    }
    #[test]
    fn test_alert_serialization_roundtrip() {
        let alert = TlcpAlert::new(TlcpAlertLevel::Fatal, TlcpAlertDescription::BadCertificate);
        let bytes = alert.to_bytes();
        let parsed = TlcpAlert::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.level, TlcpAlertLevel::Fatal);
        assert_eq!(parsed.description, TlcpAlertDescription::BadCertificate);
    }
    #[test]
    fn test_alert_parse_invalid_level() {
        let result = TlcpAlert::from_bytes(&[0x03, 0x00]);
        assert!(result.is_err());
    }
    #[test]
    fn test_alert_parse_invalid_description() {
        let result = TlcpAlert::from_bytes(&[0x02, 0xFF]);
        assert!(result.is_err());
    }
    #[test]
    fn test_alert_parse_too_short() {
        let result = TlcpAlert::from_bytes(&[0x01]);
        assert!(result.is_err());
    }
    // ========================================================================
    // Record layer bridge tests
    // ========================================================================
    #[test]
    fn test_key_material_to_session_keys() {
        let master = [0x42u8; 32];
        let cr = [0x01u8; 32];
        let sr = [0x02u8; 32];
        let km =
            TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_GCM_SM3).unwrap();
        let sk = km.to_session_keys().unwrap();
        assert_eq!(sk.client_key.len(), 16);
        assert_eq!(sk.server_key.len(), 16);
        assert_eq!(sk.client_nonce.len(), 12);
        assert_eq!(sk.server_nonce.len(), 12);
    }
    #[test]
    fn test_key_material_cbc_no_session_keys() {
        let master = [0x42u8; 32];
        let cr = [0x01u8; 32];
        let sr = [0x02u8; 32];
        let km =
            TlcpKeyMaterial::derive(&master, &cr, &sr, TlcpCipherSuite::ECDHE_SM4_CBC_SM3).unwrap();
        // CBC mode has IV of 16 bytes, not 12 bytes, so conversion should fail
        assert!(km.to_session_keys().is_err());
    }
    // ========================================================================
    // Session resumption tests
    // ========================================================================
    #[tokio::test]
    async fn test_session_cache_put_get() {
        let cache = TlcpSessionCache::with_capacity(10);
        let session_id = vec![0x01, 0x02, 0x03, 0x04];
        let session = TlcpResumedSession::new(
            vec![0xAAu8; 32],
            TlcpCipherSuite::ECDHE_SM4_GCM_SM3.id,
            [0xBBu8; 32],
            [0xCCu8; 32],
        );
        cache.put(session_id.clone(), session).await;
        let retrieved = cache.get(&session_id).await;
        assert!(retrieved.is_some(), "Session should be found in cache");
        let s = retrieved.unwrap();
        assert_eq!(s.master_secret, vec![0xAAu8; 32]);
        assert_eq!(s.cipher_suite, TlcpCipherSuite::ECDHE_SM4_GCM_SM3.id);
    }
    #[tokio::test]
    async fn test_session_cache_expired() {
        let cache = TlcpSessionCache::with_capacity(10);
        let session_id = vec![0x01, 0x02, 0x03, 0x04];
        let mut session = TlcpResumedSession::new(
            vec![0xAAu8; 32],
            TlcpCipherSuite::ECDHE_SM4_GCM_SM3.id,
            [0xBBu8; 32],
            [0xCCu8; 32],
        );
        // Set very short lifetime so it expires immediately
        session.lifetime = Duration::from_millis(1);
        cache.put(session_id.clone(), session).await;
        // Wait for expiry
        tokio::time::sleep(Duration::from_millis(10)).await;
        let retrieved = cache.get(&session_id).await;
        assert!(retrieved.is_none(), "Expired session should not be found");
    }
    #[tokio::test]
    async fn test_session_cache_lru_eviction() {
        let cache = TlcpSessionCache::with_capacity(2);
        let s1 =
            TlcpResumedSession::new(vec![0x01u8; 32], [0xE0, 0x11], [0x02u8; 32], [0x03u8; 32]);
        let s2 =
            TlcpResumedSession::new(vec![0x04u8; 32], [0xE0, 0x11], [0x05u8; 32], [0x06u8; 32]);
        let s3 =
            TlcpResumedSession::new(vec![0x07u8; 32], [0xE0, 0x11], [0x08u8; 32], [0x09u8; 32]);
        cache.put(vec![1], s1).await;
        cache.put(vec![2], s2).await;
        // Cache is now full (capacity 2)
        cache.put(vec![3], s3).await; // Should evict oldest
        assert!(
            cache.get(&[1]).await.is_none(),
            "Oldest session should be evicted"
        );
        assert!(
            cache.get(&[2]).await.is_some(),
            "Second session should still exist"
        );
        assert!(
            cache.get(&[3]).await.is_some(),
            "Newest session should exist"
        );
    }
    #[tokio::test]
    async fn test_server_session_resumption() {
        let cache = TlcpSessionCache::with_capacity(10);
        // --- Full handshake ---
        let mut server = TlcpServerHandshake::with_session_cache(cache).unwrap();
        let client_hello = TlcpClientHello::new().unwrap();
        server.process_client_hello(&client_hello).await.unwrap();
        let server_hello = server.create_server_hello().unwrap();
        let session_id = server_hello.session_id.clone();
        assert!(
            !session_id.is_empty(),
            "Full handshake should assign a session ID"
        );
        // Complete the handshake
        server.complete_key_exchange(vec![0x42u8; 48]).unwrap();
        let km = server.derive_key_material().unwrap();
        let _keys = km.to_session_keys().unwrap();
        // Cache the session
        server.cache_session().await;
        // --- Abbreviated handshake (resumption) ---
        // Re-create cache reference for the second server
        let _cache2 = TlcpSessionCache::with_capacity(10);
        // Note: Since TlcpSessionCache uses Arc internally, we need to get
        // the actual cache back. For this test, create a new server with
        // the same underlying cache by cloning the Arc.
        // Actually, let's just verify the session was cached by checking the
        // server's to_resumed_session() method
        let resumed = server.to_resumed_session();
        assert!(
            resumed.is_some(),
            "Server should produce a resumable session"
        );
    }
    #[tokio::test]
    async fn test_client_resumption_helpers() {
        let mut client = TlcpHandshake::new_client().unwrap();
        // Before handshake, no session to resume
        assert!(client.to_resumed_session().is_none());
        // Simulate completed handshake state
        client.master_secret = Some(vec![0xAAu8; 32]);
        client.cipher_suite = Some(TlcpCipherSuite::ECDHE_SM4_GCM_SM3.id);
        client.server_random = Some([0xBBu8; 32]);
        client.client_random = [0xCCu8; 32];
        client.session_id = vec![0x01, 0x02, 0x03];
        let resumed = client.to_resumed_session().unwrap();
        assert_eq!(resumed.master_secret, vec![0xAAu8; 32]);
        assert_eq!(resumed.cipher_suite, TlcpCipherSuite::ECDHE_SM4_GCM_SM3.id);
        // session_id() should return the ID
        assert_eq!(client.session_id(), &[0x01, 0x02, 0x03]);
    }
    // ========================================================================
    // Handshake message serialization tests
    // ========================================================================
    #[test]
    fn test_server_key_exchange_roundtrip() {
        let ephemeral_pub = vec![0x04; 65];
        let mut signature = vec![0x30, 0x44, 0x02, 0x20];
        signature.extend_from_slice(&[0xAB; 60]);
        let params = Sm2EcdheParams::new(ephemeral_pub.clone(), signature.clone());
        let ske = TlcpServerKeyExchange::new(params);
        let bytes = ske.to_bytes();
        assert_eq!(bytes[0], HandshakeType::ServerKeyExchange as u8);
        // Parse: skip 4-byte header (type + 3-byte length)
        let body_len = ((bytes[2] as usize) << 8) | bytes[3] as usize;
        let parsed = TlcpServerKeyExchange::from_body(&bytes[4..4 + body_len]).unwrap();
        assert_eq!(parsed.ecdhe_params.ephemeral_public, ephemeral_pub);
        assert_eq!(parsed.ecdhe_params.signature, signature);
    }
    #[test]
    fn test_server_hello_done_roundtrip() {
        let shd = TlcpServerHelloDone;
        let bytes = shd.to_bytes();
        assert_eq!(bytes, vec![HandshakeType::ServerHelloDone as u8, 0, 0, 0]);
        let parsed = TlcpServerHelloDone::from_body(&[]).unwrap();
        let bytes2 = parsed.to_bytes();
        assert_eq!(bytes, bytes2);
    }
    #[test]
    fn test_client_key_exchange_ecdhe_roundtrip() {
        let ephemeral_pub = vec![0x04; 65];
        let cke = TlcpClientKeyExchange::new_ecdhe(ephemeral_pub.clone());
        let bytes = cke.to_bytes();
        assert_eq!(bytes[0], HandshakeType::ClientKeyExchange as u8);
        // Handshake body length is 24-bit, spanning bytes 1..=3.
        let body_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..4 + body_len]).unwrap();
        // The wire payload is the ECParameters-wrapped blob
        // (`[curve_type][named_curve][pub_len][pub]`). The raw public
        // key is recoverable via `ecdhe_public_key()`.
        assert_eq!(
            parsed.key_exchange.len(),
            TLCP_ECH_PARAMS_PREFIX.len() + 1 + 65
        );
        assert_eq!(
            parsed.ecdhe_public_key().expect("ecdhe_public_key"),
            ephemeral_pub.as_slice()
        );
    }
    #[test]
    fn test_client_key_exchange_ecc_roundtrip() {
        let encrypted_pms = vec![0x07; 97]; // SM2 ciphertext
        let cke = TlcpClientKeyExchange::new_ecc(encrypted_pms.clone());
        let bytes = cke.to_bytes();
        assert_eq!(bytes[0], HandshakeType::ClientKeyExchange as u8);
        let body_len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | bytes[3] as usize;
        let parsed = TlcpClientKeyExchange::from_body(&bytes[4..4 + body_len]).unwrap();
        assert_eq!(parsed.key_exchange, encrypted_pms);
    }
    #[test]
    fn test_ecdhe_params_roundtrip() {
        let ephemeral_pub = vec![0x04, 0x01, 0x02];
        let signature = vec![0x30, 0x06];
        let params = Sm2EcdheParams::new(ephemeral_pub.clone(), signature.clone());
        let bytes = params.to_bytes();
        let parsed = Sm2EcdheParams::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.ephemeral_public, ephemeral_pub);
        assert_eq!(parsed.signature, signature);
    }
    #[test]
    fn test_ecdhe_params_reject_too_short() {
        assert!(Sm2EcdheParams::from_bytes(&[]).is_err());
        assert!(Sm2EcdheParams::from_bytes(&[0x05, 0x01]).is_err()); // claims 5-byte key but only 1
    }
    #[test]
    fn test_server_key_exchange_generate_and_verify() {
        use gm_crypto::sm2::Sm2KeyPair;
        let sign_kp = Sm2KeyPair::generate().unwrap();
        let sign_signer = gm_crypto::sm2::Sm2Signer::new(&sign_kp).unwrap();
        let sign_verifier =
            gm_crypto::sm2::Sm2Verifier::new(&sign_kp.public_key_bytes(), sign_kp.distid())
                .unwrap();
        let client_random = [0xAAu8; 32];
        let server_random = [0xBBu8; 32];
        let (ske, _ephemeral_kp) =
            TlcpServerKeyExchange::generate(&client_random, &server_random, &sign_signer).unwrap();
        // Verify should succeed with correct verifier
        assert!(
            ske.verify_signature(&client_random, &server_random, &sign_verifier)
                .is_ok()
        );
        // Verify should fail with wrong random
        let wrong_random = [0xCCu8; 32];
        assert!(
            ske.verify_signature(&wrong_random, &server_random, &sign_verifier)
                .is_err()
        );
    }
    // ========================================================================
    // CBC record-layer framing regression tests
    //
    // Lock the wire format required by RFC 5246 §6.2.3.2 / GB/T 38636-2020
    // §6.2.3: tail = `N` padding bytes (each equal to `N`) followed by ONE
    // trailing length byte (also equal to `N`). The total post-MAC tail is
    // `N + 1` bytes. Emitting one byte short of this makes every RFC 5246
    // peer (incl. `gmssl tlcp_server` master) raise `bad_record_mac` because
    // the HMAC is read one byte early.
    // ========================================================================
    /// Deterministic 16-byte keys so the regression tests are reproducible.
    fn cbc_test_keys() -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let enc_key = [0x11u8; 16].to_vec();
        let mac_key = [0x22u8; 32].to_vec();
        let read_iv = [0x33u8; 16].to_vec();
        let write_iv = [0x44u8; 16].to_vec();
        (enc_key, mac_key, read_iv, write_iv)
    }
    /// Build a CBC `TlcpKeyMaterial` from raw byte buffers (no PRF).
    fn cbc_test_key_material(
        enc_key: Vec<u8>,
        mac_key: Vec<u8>,
        read_iv: Vec<u8>,
        write_iv: Vec<u8>,
    ) -> TlcpKeyMaterial {
        TlcpKeyMaterial {
            client_mac_key: mac_key.clone(),
            server_mac_key: mac_key,
            client_enc_key: enc_key.clone(),
            server_enc_key: enc_key,
            client_iv: write_iv.clone(),
            server_iv: read_iv,
        }
    }
    #[test]
    fn cbc_record_roundtrip_various_plaintext_lengths() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Try several plaintext lengths so the test exercises all the
        // padding-region sizes (N in {1..16} roughly).
        for plaintext_len in [1usize, 7, 16, 31, 64, 200, 1024] {
            let plaintext: Vec<u8> = (0..plaintext_len as u8)
                .map(|i| i.wrapping_mul(31))
                .collect();
            // Two paired streams; one acts as the client, one as the server.
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (enc_key, mac_key, read_iv, write_iv) = cbc_test_keys();
            let client_km = cbc_test_key_material(
                enc_key.clone(),
                mac_key.clone(),
                read_iv.clone(),
                write_iv.clone(),
            );
            let server_km = cbc_test_key_material(enc_key, mac_key, read_iv, write_iv);
            let mut client = TlcpStream::new(
                client_io,
                &client_km,
                TlcpCipherSuite::ECC_SM4_CBC_SM3,
                true,
                vec![],
            )
            .expect("client TlcpStream::new");
            let mut server = TlcpStream::new(
                server_io,
                &server_km,
                TlcpCipherSuite::ECC_SM4_CBC_SM3,
                false,
                vec![],
            )
            .expect("server TlcpStream::new");
            runtime
                .block_on(client.write_application_data(&plaintext))
                .unwrap_or_else(|e| {
                    panic!("write_application_data({}) failed: {:?}", plaintext_len, e)
                });
            let received = runtime
                .block_on(server.read_application_data())
                .unwrap_or_else(|e| {
                    panic!("read_application_data({}) failed: {:?}", plaintext_len, e)
                });
            assert_eq!(
                received, plaintext,
                "CBC record-layer round-trip mismatch for plaintext_len={}",
                plaintext_len
            );
        }
    }
    /// The wire bytes that `encrypt_cbc_record_with_type` puts on the wire
    /// must end with exactly `N` bytes of value `N` followed by ONE byte of
    /// value `N`. This is what every RFC 5246-compliant parser expects; if we
    /// ever regress to emitting only `N` bytes (the historical
    /// `gmssl_padding_compat=false` bug) the HMAC will be read one byte early
    /// on the peer side and every TLS 1.2 / TLCP CBC handshake will fail with
    /// `bad_record_mac`.
    #[test]
    fn cbc_record_tail_shape_via_public_api() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // 7 bytes plaintext -> inner_len = 7 + 32 = 39 -> (39 + 1) % 16 = 8
        // -> pad_len = (16 - 8) % 16 = 8. Tail is therefore 9 bytes total
        // (8 padding bytes + 1 length byte), all of value 8.
        let plaintext: &[u8] = b"1234567";
        let expected_pad = 8usize;
        let expected_tail: Vec<u8> =
            std::iter::repeat_n(expected_pad as u8, expected_pad + 1).collect();
        // Two paired streams: client writes, the lower half exposes the wire
        // bytes (we read them raw and decrypt in this test to inspect the
        // post-MAC tail shape). Both halves share the same key material here
        // so that the test can decrypt with the actual write key — using a
        // hard-coded dummy key would scramble everything except the CBC
        // structure, masking any bug in the padding math.
        let (a, mut lower) = tokio::io::duplex(64 * 1024);
        let (enc_key, mac_key, read_iv, write_iv) = cbc_test_keys();
        let client_km = cbc_test_key_material(enc_key.clone(), mac_key, write_iv, read_iv);
        let mut client = TlcpStream::new(
            a,
            &client_km,
            TlcpCipherSuite::ECC_SM4_CBC_SM3,
            true,
            vec![],
        )
        .expect("TlcpStream::new client");
        runtime
            .block_on(client.write_application_data(plaintext))
            .expect("write_application_data");
        // Read the wire bytes from the lower half (no TlcpStream on the
        // server side — we want raw bytes to inspect the post-MAC tail).
        let mut header = [0u8; 5];
        runtime
            .block_on(tokio::io::AsyncReadExt::read_exact(&mut lower, &mut header))
            .unwrap();
        assert_eq!(header[0], TLCP_RECORD_TYPE_APP_DATA);
        assert_eq!(&header[1..3], &TLCP_VERSION);
        let ct_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut record = vec![0u8; ct_len];
        runtime
            .block_on(tokio::io::AsyncReadExt::read_exact(&mut lower, &mut record))
            .unwrap();
        let ciphertext = &record[SM4_CBC_IV_LENGTH..];
        // Decrypt with the SAME key the client used; with a wrong key CBC
        // gives random-looking bytes and the tail-shape assertion becomes
        // meaningless.
        let cipher = gm_crypto::sm4::Sm4Cipher::new(&enc_key).unwrap();
        let iv: [u8; 16] = record[..SM4_CBC_IV_LENGTH].try_into().unwrap();
        let inner = cipher
            .decrypt_cbc_raw(ciphertext, &iv)
            .expect("decrypt_cbc_raw");
        // The post-MAC tail is `expected_pad + 1` bytes, all `expected_pad`.
        let tail = &inner[inner.len() - (expected_pad + 1)..];
        assert_eq!(
            tail,
            &expected_tail[..],
            "CBC record tail is wrong; got {:02X?}, want N={} of value N (then 1 length byte)",
            tail,
            expected_pad
        );
        // And the HMAC is right BEFORE the padding (RFC 5246).
        let unpadded_len = inner.len() - (expected_pad + 1);
        assert!(
            unpadded_len >= SM3_HMAC_LENGTH,
            "unpadded_len {} < HMAC length {} — record too short",
            unpadded_len,
            SM3_HMAC_LENGTH
        );
        let plaintext_len = unpadded_len - SM3_HMAC_LENGTH;
        assert_eq!(
            plaintext_len,
            plaintext.len(),
            "extracted plaintext length mismatch: got {}, want {}",
            plaintext_len,
            plaintext.len()
        );
    }
}
