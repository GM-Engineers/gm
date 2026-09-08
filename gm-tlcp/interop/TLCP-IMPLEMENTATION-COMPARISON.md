# TLCP Implementation Compliance Audit — Deep Comparison

Status: pure analysis, no code changes. Scope: GB/T 38636-2020 (TLCP) and its
predecessor GM/T 0024-2014 (SSL VPN) as implemented by **GmSSL master**,
**openHiTLS (the local openhitls/ tree)**, **Tongsuo 8.3.0**, and
**gm-tlcp 0.2.0**.

This document records what each implementation actually contains, where each
diverges from the GB/T standard text, and where they interop despite the
divergence. Recommendations are clearly separated from verified findings; no implementation changes are made by this document.

---

## 1. The reference standard

GB/T 38636-2020 ("TLCP") is the modern Chinese national standard for
state-administered transport-layer crypto. It builds on GB/T 32918 (SM2),
GB/T 32905 (SM3), GB/T 32907 (SM4), and GB/T 38635 (SM9). It is the
successor to GM/T 0024-2014 (SSL VPN tech spec). Per Tony Bai's write-up
(2022-07-17), the national standard "基本兼容" the industry standard, with
the main changes being (a) adding the GCM cipher suites and (b) **removing
the SM1-based cipher suites** that the industry standard had allowed.

**Correction to that earlier characterization** — RSA-based suites (0xE019,
0xE01C, 0xE059, 0xE05A) are **still present** in GB/T 38636-2020. Two
independent sources confirm this:
1. `xuyang2/ntls-notes` (a TLCP-focused note repository) transcribes the
   full 12-suite table from the national standard, including the four
   RSA suites.
2. `Trisia/gotlcp` (a Go TLCP library that explicitly cites GB/T
   38636-2020 §6.4.5.9) lists all four RSA suites.

TonyBai's "removed RSA" line is not corroborated by either the cipher-suite
table or by an independent implementation that claims spec compliance.
Treat TonyBai's note as authoritative only for the **SM1 removal**, not
for any RSA-suite removal.

### 1.1 Cipher suite table (GB/T 38636-2020)

The 12 cipher suites from the national standard (sourced from **GB/T 38636-2020 §6.4.5.2.1 表 2 (密码规格)**
(independently transcribed by `xuyang2/ntls-notes` and `Trisia/gotlcp`; their transcripts were used here only to cross-check the standard's own table)):

| ID | Name | Kex | Cipher | MAC |
| --- | --- | --- | --- | --- |
| 0xE011 | ECDHE_SM4_CBC_SM3 | ECDHE (SM2) | SM4-CBC | SM3 |
| 0xE013 | ECC_SM4_CBC_SM3 | ECC (SM2) | SM4-CBC | SM3 |
| 0xE015 | IBSDH_SM4_CBC_SM3 | IBSDH (SM9) | SM4-CBC | SM3 |
| 0xE017 | IBC_SM4_CBC_SM3 | IBC (SM9) | SM4-CBC | SM3 |
| 0xE019 | RSA_SM4_CBC_SM3 | RSA | SM4-CBC | SM3 |
| 0xE01C | RSA_SM4_CBC_SHA256 | RSA | SM4-CBC | SHA-256 |
| 0xE051 | ECDHE_SM4_GCM_SM3 | ECDHE (SM2) | SM4-GCM | SM3 |
| 0xE053 | ECC_SM4_GCM_SM3 | ECC (SM2) | SM4-GCM | SM3 |
| 0xE055 | IBSDH_SM4_GCM_SM3 | IBSDH (SM9) | SM4-GCM | SM3 |
| 0xE057 | IBC_SM4_GCM_SM3 | IBC (SM9) | SM4-GCM | SM3 |
| 0xE059 | RSA_SM4_GCM_SM3 | RSA | SM4-GCM | SM3 |
| 0xE05A | RSA_SM4_GCM_SHA256 | RSA | SM4-GCM | SHA-256 |

The Kex column reflects the standard's own annotation in §6.4.5.2.1: the
`ECC-ECDHE` pair uses SM2 (curve per GB/T 32918.3-2016 / GB/T 35276), and
the `IBC-IBSDH` pair uses SM9 (per GM/T 0044-2016). The `rsa_sign`
cert type used by the RSA / ECC suites is registered as type `64`
(`ecdsa_sign`) in §6.4.5.5 because SM2 reuses the ECDSA private-key
usage.

GM/T 0024-2014 (industry predecessor) had a parallel set with SM1 and
SHA-1 variants (0xE001..0xE00A, 0xE01A) which are **not** in the national
standard.

### 1.2 What GB/T 38636 actually requires for ECDHE

Extracted from the SM2 key-agreement protocol as referenced by GB/T 38636-2020 §6.4.6.2.
The 2012 industrial predecessor GM/T 0003.3-2012 §6.1 (and its equivalent in
GB/T 32918.3-2016) is the canonical text:

```
User B (responder) steps:
  B4: tB = (dB + x̂2 · rB) mod n      where x̂2 = 2^127 + (x2 & (2^127 - 1))
  B6: V  = [h · tB](PA + [x̂1]RA)      where x̂1 = 2^127 + (x1 & (2^127 - 1))
  B7: KB = KDF(xV ∥ yV ∥ ZA ∥ ZB, klen)

User A (initiator) steps:
  A5: tA = (dA + x̂1 · rA) mod n      where x̂1 = x̂(RA.x) (own ephemeral)
  A7: U  = [h · tA](PB + [x̂2]RB)      where x̂2 = x̂(RB.x) (peer ephemeral)
  A8: KA = KDF(xU ∥ yU ∥ ZA ∥ ZB, klen)
```

A KAT of `KA = KB = 55B0AC62A6B927BA23703832C853DED4` appears in GM/T 0003.3-2012 Annex A for the same algorithm; we did not have the GB/T 32918.3-2016 Annex A.2 text in this audit, so the KAT is cited from the 2012 text and the equivalence with the 2016 version is asserted but not directly re-verified.

The normative role mapping is important: in TLCP the server sends the
ServerKeyExchange first, so the server is user A (initiator) and the client is
user B (responder). Both parties use the fixed KDF order `ZA ∥ ZB`; the order is
not swapped for the responder.

---

## 2. Per-implementation analysis

### 2.1 GmSSL master (this tree, gmssl-master/)

**Size:** `src/tlcp.c` is 2572 LOC, single translation unit, no separate
client/server split. Reference CLI in `tools/tlcp_client.c` and
`tools/tlcp_server.c`.

**Cipher suites actually wired up:** The `tlcp_cipher_suites[]` array in
`src/tlcp.c:39-43` lists only:

```c
TLS_cipher_ecc_sm4_cbc_sm3,
TLS_cipher_ecc_sm4_gcm_sm3,
TLS_cipher_ecdhe_sm4_cbc_sm3,
TLS_cipher_ecdhe_sm4_gcm_sm3,
```

Four of the twelve spec suites. The other eight are declared in
`include/gmssl/tls.h:90-101` but not added to the active list. The header
defines helpers `tlcp_cipher_suite_is_ecc()` and
`tlcp_cipher_suite_is_ecdhe()` which only return true for the two
respective pairs; there are no `is_ibc`, `is_ibsdh`, or `is_rsa` helpers.

The IBC/RSA/IBSDH suites are described in **comments only**
(`src/tlcp.c:50-117`): design notes sketching `sm9_encrypt(ibc_parameter,
ibc_id)` for IBC, etc. There is no code path that exercises them.
Concretely:

- `tlcp_recv_server_key_exchange` (around line 978/1021) branches on
  `is_ecdhe()` / `is_ecc()` / `else { internal_error }`.
- `tlcp_send_client_key_exchange`, `tlcp_generate_pre_master_secret`,
  `tlcp_check_pre_master_secret` all branch on the same pair.
- For any non-ECC/non-ECDHE suite, GmSSL responds with
  `TLS_alert_internal_error` and drops the connection.

So **GmSSL master TLCP is functionally limited to four cipher suites**
even though it ships the constant names for all twelve.

**Static curves:** only `TLS_curve_sm2p256v1`. No other named curves.

**Static signature algorithms:** only `TLS_sig_sm2sig_sm3`.

**Signature in SKE (ECDHE):** `SM2_sign(client_random || server_random ||
server_ecdh_params)` — matches spec §6.4.5.
**Signature in SKE (ECC):** `SM2_sign(client_random || server_random ||
enc_cert_len_3bytes || enc_cert)` — signature is over the enc cert
itself, no ephemeral. Matches what GmSSL documents.

**Session resumption / abbreviated handshake:** Not implemented.
`grep -nE 'resume|abbreviated' src/tlcp.c` returns nothing. The state
machine goes straight from SKE through CKE/CV/CCS/Finished without any
session-ID lookup or branch for an abbreviated flow.

**Cipher suite KDF / PMS computation (the SM2 ECDHE core):**

```c
// src/sm2_exch.c, sm2_key_exchange(), with is_initiator flag:
if (is_initiator) {
    sm2_compute_z(za, &key->public_key, id, idlen);              // za = SELF
    sm2_compute_z(zb, &peer_public_key->public_key, peer_id, peer_idlen);  // zb = PEER
} else {
    sm2_compute_z(za, &peer_public_key->public_key, peer_id, peer_idlen);  // za = PEER
    sm2_compute_z(zb, &key->public_key, id, idlen);              // zb = SELF
}
sm2_z256_point_get_x_hat(&key_exchange->public_key, local_x_hat);
sm2_z256_point_get_x_hat(&peer_point, peer_x_hat);
sm2_z256_modn_mul(t, local_x_hat, key_exchange->private_key);
sm2_z256_modn_add(t, t, key->private_key);
sm2_z256_point_mul(&point, peer_x_hat, &peer_point);
sm2_z256_point_add(&point, &peer_public_key->public_key, &point);
sm2_z256_point_mul(&point, t, &point);
sm2_z256_point_to_bytes(&point, kdf_input);          // 64 bytes (x || y)
memcpy(kdf_input + 64, za, 32);                       // za  ← responder's Z
memcpy(kdf_input + 96, zb, 32);                       // zb  ← initiator's Z
sm2_kdf(kdf_input, sizeof(kdf_input), shared_key_len, shared_key);
```

Two observations:

- The x̂ direction is `t = x̂(own_ephemeral) * r_own + d_own`, shared =
  `peer_ephemeral_pub * x̂(peer_ephemeral) + peer_static_pub`. That
  matches the spec.
- The KDF input order is `xV ∥ yV ∥ za ∥ zb` where `za = "the first Z
  computed"`. The variable name `za` is misleading — it is *not* always
  ZA.

Walking through the call sites:

| Site | Call | is_initiator | meaning of `za` | meaning of `zb` | KDF input |
| --- | --- | --- | --- | --- | --- |
| Client sends CKE (`tlcp_send_client_key_exchange`, line ~1190) | `sm2_key_exchange(0, enc_key, enc_peer_pub, ...)` | 0 (false) | Z of peer = server Z = **ZB** | Z of self = client Z = **ZA** | `xV ∥ yV ∥ ZA ∥ ZB` |
| Server processes CKE (`tlcp_recv_client_key_exchange`, line ~2097) | `sm2_key_exchange(1, enc_key, enc_peer_pub, ...)` | 1 (true) | Z of self = server Z = **ZB** | Z of peer = client Z = **ZA** | `xV ∥ yV ∥ ZA ∥ ZB` |

The call sites map the roles correctly: server=A/initiator and client=B/responder. The server computes self ZA then peer ZB; the client computes peer ZA then self ZB. Both produce `ZA ∥ ZB`. The `is_initiator` flag is not semantically backwards.

**Length-prefix on CKE body:** GmSSL wraps the CKE body with a 2-byte length prefix via
`tls_uint16array_to_bytes(...)`. (Symbol name and call site re-confirmed in
the source: the write path lives in the ECDHE branch of `tlcp_send_client_key_exchange`
in `gmssl-master/src/tlcp.c`; line numbers may shift across master commits.) The spec
(RFC 5246 §7.4.7 / GB/T 38636-2020 §6.4.1.6) says the body is `opaque
body<0..2^24-1>` with the length encoded in the 24-bit handshake header —
no extra u16 prefix on the body. This is a second GmSSL deviation, but
it only affects wire-format interop, not crypto.

### 2.2 openHiTLS (this tree, openhitls/openhitls/)

**Size:** TLCP support is spread across `tls/handshake/{send,recv,parse,
pack,common}` and the SM2 crypto module `crypto/sm2/src/`. The build-time
gate is `HITLS_TLS_PROTO_TLCP11` (the protocol version is
`HITLS_VERSION_TLCP_DTLCP11 = 0x0101u`).

**Cipher suites actually wired up (from `tls/config/src/cipher_suite.c`
+ `tls/include/cipher_suite.h`):**

| ID | Name | Status |
| --- | --- | --- |
| 0xE011 | ECDHE_SM4_CBC_SM3 | active |
| 0xE013 | ECC_SM4_CBC_SM3 | active |
| 0xE051 | ECDHE_SM4_GCM_SM3 | active |
| 0xE053 | ECC_SM4_GCM_SM3 | active |

Four suites. Missing the four IBC/IBSDH suites and all four RSA suites.
openHiTLS's `tls/handshake/pack/src/pack_extensions.c` has a cert-type
table at line 1682-1697 that registers the four SM4 suites and the two
TLS 1.3 SM4 suites; nothing else.

**Static curves:** `HITLS_EC_GROUP_SM2 = 0x0029`. Only one curve.

**Handshake messages:** openHiTLS has the full ClientHello, ServerHello,
Certificate (with two cert entries: sign + enc), ServerKeyExchange,
CertificateRequest, ServerHelloDone, Certificate, ClientKeyExchange,
CertificateVerify, ChangeCipherSpec, Finished. The state machine walks
through them in the spec order.

**Session resumption / abbreviated handshake:** Yes, inherited from the
generic TLS 1.2 abbreviated path in `tls/handshake/send/src/...` — the
NTLS-specific files don't add a special case but the generic machinery
covers TLCP because it shares the wire format.

**CKE wire format for ECDHE (TLCP):**
```c
// tls/handshake/pack/src/pack_client_key_exchange.c
static int32_t PackDtlcpbytes(...) {           // TLCP only
    PackAppendUint8ToBuf(pkt, HITLS_EC_CURVE_TYPE_NAMED_CURVE);  // 1 byte
    PackAppendUint16ToBuf(pkt, HITLS_EC_GROUP_SM2);             // 2 bytes (u16 named_curve!)
}
```
So TLCP CKE = `curve_type (1) || named_curve (u16, 2 bytes) || pubkey_len (u8, 1) || pubkey (65)`. No outer u16 prefix on the CKE body. **This is the spec-compliant shape.**

**PMS computation (ECDHE TLCP):**

```c
// crypto/sm2/src/sm2_exch.c, CRYPT_SM2_KapComputeKey
BN_ModMul(t, xs, selfCtx->r, order, opt);
BN_ModAddQuick(t, t, selfCtx->pkey->prvkey, order, opt);     // t = xs * r + d
EC_PointMul(peerCtx->pkey->para, uorv, xp, peerCtx->pointR);
EC_PointAddAffine(selfCtx->pkey->para, uorv, uorv, peerCtx->pkey->pubkey);
EC_PointMul(selfCtx->pkey->para, uorv, t, uorv);            // uorv = (xp * peerR + peerPub) * t
```

And the KDF assembly in `Sm2CalculateKey`:

```c
if (selfCtx->server == 1) {
    /* SIDE A, Z_A || Z_B, server is initiator(Z_A), client is responder(Z_B) */
    sm2_compute_z_digest(selfCtx, ...);  // self
}
sm2_compute_z_digest(peerCtx, ...);     // peer
if (selfCtx->server == 0) {
    /* SIDE B */
    sm2_compute_z_digest(selfCtx, ...);  // self
}
ecdh_KDF_X9_63(out, outlen, buf + 1, idx - 1, NULL, 0, md);
```

For the server (`server=1`), self ZA is emitted first and peer ZB second. For the client (`server=0`), peer ZA is emitted first and self ZB second. Both therefore produce the normative `xV ∥ yV ∥ ZA ∥ ZB`. The source comments correctly identify server=A/initiator.

**ECC suite (no ECDHE):** `tls/handshake/send/src/send_client_key_exchange.c:GenerateEccPremasterSecret`:
```c
BSL_Uint16ToByte(ctx->config.tlsConfig.maxVersion, premasterSecret);  // 2 bytes
SAL_CRYPT_Rand(..., &premasterSecret[offset], MASTER_SECRET_LEN - offset);  // 46 random
```
PMS = `client_version (2) || random (46)` = 48 bytes. **Standard TLS 1.0
PMS format. Matches spec.**

### 2.3 Tongsuo 8.3.0 (this tree, tongsuo/Tongsuo-8.3.0/)

**Naming convention:** Tongsuo calls its TLCP implementation **NTLS**
(National TLS). All TLCP code lives under `ssl/statem_ntls/` with a
`statem_ntls_{clnt,srvr}.c` split mirroring the main OpenSSL state
machine. Protocol version is `NTLS1_1_VERSION = 0x0101`.

**Cipher suites** (from `include/openssl/ntls.h:48-72`):
- 0xE011, 0xE013, 0xE015, 0xE017, 0xE019, 0xE01C, 0xE051, 0xE053, 0xE055,
  0xE057, 0xE059, 0xE05A — all 12.

All twelve suite IDs are declared, and eight of them (the four ECDHE/ECC pairs plus the four RSA suites) are wired up as active cipher suite entries in `ssl/s3_lib.c`. The four SM9 suites (IBSDH/IBC) are declared as constants but the SM2DHE dispatcher in `statem_ntls_*` does not route to them, so they are not functional.

So Tongsuo has the broadest cipher-suite *declaration* of the three reference implementations and the broadest actively wired-up set (8 suites including the four RSA ones), but still does not implement SM9.

**RSA handling** in NTLS uses standard OpenSSL EVP (`EVP_PKEY_encrypt`)
with PKCS#1 v1.5 padding (`RSA_PKCS1_PADDING`) — note the academic
warning from the Springer paper: TLCP-with-RSA-v1.5 is theoretically
vulnerable to DROWN-style attacks.

**PMS computation (ECDHE TLCP):**

```c
// crypto/sm2/sm2_kep.c, SM2_compute_key
if (server) {
    sm2_compute_z_digest(..., self_uid, ..., self_eckey);   // self Z
}
sm2_compute_z_digest(..., peer_uid, ..., peer_pub_key);       // peer Z
if (!server) {
    sm2_compute_z_digest(..., self_uid, ..., self_eckey);   // self Z
}
ecdh_KDF_X9_63(out, outlen, buf + 1, idx - 1, NULL, 0, md);
```

For `server=1`: self Z (= ZA) first, peer Z (= ZB) second.
For `server=0`: peer Z (= ZA) first, self Z (= ZB) second.

**KDF input on both sides: `xV ∥ yV ∥ ZA ∥ ZB`. Spec-conformant.**

The Tongsuo source comment `// Z_A || Z_B, server is initiator(Z_A)` is consistent with TLCP: server is initiator.

**CKE wire format (ECDHE):** `ntls_construct_cke_sm2dhe` at
`ssl/statem_ntls/statem_ntls_clnt.c:467-525` writes the body directly
with no outer u16 prefix:
```c
WPACKET_put_bytes_u8(pkt, NAMED_CURVE_TYPE);   // 0x03
WPACKET_put_bytes_u8(pkt, 0);                  // named_curve high byte
WPACKET_put_bytes_u8(pkt, curve_id);           // named_curve low byte
WPACKET_sub_memcpy_u8(pkt, encodedPoint, encodedlen);
```
`WPACKET_sub_memcpy_u8` writes a u8 length then the bytes, so the body
is exactly `03 00 29 || pub_len || pub` — the same 69 bytes as openHiTLS.
The encrypted static-ECC / RSA CKE path (`ntls_construct_cke_sm2` and
`ntls_construct_cke_rsa`) is a different function and **does** write a
u16 length prefix on the encrypted payload, matching the static-ECC/RSA
framing used by GmSSL master and openHiTLS.

Looking at Tongsuo's SKE in `statem_ntls_srvr.c` (line 22-75): the SKE
uses the same 3-byte header + 1-byte length + pub envelope (named
`tlcp_server_key_exchange_params` in TLCP). Same convention as gm-tlcp
and GmSSL.

**Session resumption:** Yes — inherited from mainline OpenSSL
`SSL_renegotiate_abbreviated` (used for renegotiation, not strictly TLCP
session resumption).

**ECC PMS (static-ECC suite):** `statem_ntls_clnt.c:530-580`,
`ntls_construct_cke_sm2`:
```c
pms[0] = s->client_version >> 8;
pms[1] = s->client_version & 0xff;
RAND_bytes(pms + 2, pmslen - 2);
```
PMS = `client_version || random(46)` = 48 bytes. **Standard TLS 1.0 PMS
format. Matches spec.**

The ECDHE CKE body has no outer u16 prefix. Its inner bytes are `03 00 29 || pub_len || pub`; only encrypted static-ECC/RSA payloads use a u16 length field. The comment in `ntls_construct_cke_sm2dhe` notes:
> "The standard TLS protocol requires no u16 len bytes before the
> encrypted PMS value. The NTLS specification is also very blurry on
> this. But major implementations require the 2 bytes length field
> (which is redundant), otherwise handshake will fail..."
The author left this comment on the encrypted-PMS u16 wrapper for interop with GmSSL master and the other major implementations.

### 2.4 gm-tlcp (this tree, gm/gm-tlcp/)

> **Note (gm-tlcp 0.3.1 / R-2, 2026-09-08):** The original text below
> describes gm-tlcp 0.2.0 as a historical snapshot. **gm-tlcp 0.3.1**
> is the current release and is the version evaluated in §3.5 below.
> The 0.2.0 text is preserved verbatim to document what was true
> before R-1 flipped the default mode. For the post-R-2 behaviour,
> see §3.5 entry "gm-tlcp 0.3.1".

#### 2.4.1 gm-tlcp 0.2.0 (historical snapshot, pre-R-1)

**Size:** `src/tlcp/` totals ~12.4k LOC across 22 files. The handshake
logic is split into `handshake/client.rs` and `handshake/server.rs`;
the main facade is `mod.rs` (3780 LOC).

**Cipher suites actually wired up** (from `src/tlcp/constants.rs:54-71`):

```rust
pub const TLS_ECDHE_SM4_GCM_SM3: [u8; 2] = [0xE0, 0x51];
pub const TLS_ECDHE_SM4_CBC_SM3: [u8; 2] = [0xE0, 0x11];
pub const TLS_ECC_SM4_GCM_SM3:   [u8; 2] = [0xE0, 0x53];
pub const TLS_ECC_SM4_CBC_SM3:   [u8; 2] = [0xE0, 0x13];
```

**Four suites.** Same narrow coverage as GmSSL master and openHiTLS.

**Static curves:** Only `sm2p256v1`.

**Static signature algorithms:** Only SM2-with-SM3.

**Static curve type / named curve:** `TLCP_EC_CURVE_TYPE_NAMED_CURVE = 0x03`,
`TLCP_NAMED_CURVE_SM2P256V1 = [0x00, 0x29]` (from `constants.rs:95-101`).

**Dual certificate handling:** `messages/cert_pair.rs` parses
`Certificate` messages as `sign_cert || enc_cert`. The
`Sm2Signer::new_with_distid` constructor (added in PR4) lets the
caller specify separate distids for the enc cert vs. the sign cert.
The full dual-cert flow is implemented.

**Session resumption / abbreviated handshake:** Partial infrastructure
exists (`src/tlcp/session.rs` has `TlcpResumedSession`,
`TlcpSessionCache`, `with_session_cache`), and the client state
machine has `is_resumed`/`resumed_session` fields. The server's
abbreviated branch appears to exist in spirit but I have not verified it
end-to-end — the integration is incomplete.

**PMS computation — formula in pms.rs** (already audited, found correct
against the spec text in our previous PR4 analysis):

```rust
let local_x_hat = scalar_from_x_hat(&local_ephemeral_x)?;   // x̂(R_local.x)
let t = local_x_hat * local_ephemeral_scalar + local_static_scalar;
let peer_x_hat = scalar_from_x_hat(&peer_ephemeral_x)?;      // x̂(R_peer.x)
let shared_point = peer_ephemeral_point * peer_x_hat + peer_static_point;
let v = shared_point * t;
// ...
let mut kdf_input = Vec::with_capacity(128);
kdf_input.extend_from_slice(&v_x);
kdf_input.extend_from_slice(&v_y);
kdf_input.extend_from_slice(z_a);
kdf_input.extend_from_slice(z_b);
sm2_kdf(&kdf_input, klen) ...
```

Verified: `t` uses x̂ of own ephemeral, `shared_point` uses x̂ of peer's
ephemeral. This matches the SM2 KAP steps as numbered in GM/T 0003.3-2012 §6.1
(B4 `tB = (dB + x̄2 · rB) mod n`; B6 `V = [h·tB](PA + [x̄1]RA)`; A5 `tA = (dA + x̄1 · rA) mod n`;
A7 `U = [h·tA](PB + [x̄2]RB)`; B7 `KB = KDF(xV ∥ yV ∥ ZA ∥ ZB, klen)`;
A8 `KA = KDF(xU ∥ yU ∥ ZA ∥ ZB, klen)`). The formula is **spec-correct**.

**PMS computation — call-site Z order (the M-2 root cause):**

The function takes `z_a, z_b` as arguments and writes them in that
order. Two call sites in `src/tlcp/mod.rs`:

| Site | `z_a` (arg 7) | `z_b` (arg 8) | KDF input |
| --- | --- | --- | --- |
| Client (`mod.rs:1948-1957`) | `z_server` | `z_client` | `xV ∥ yV ∥ ZA ∥ ZB` |
| Server (does not currently use this function — see below) | n/a | n/a | n/a |

**The client call site passes `z_server` first (Z of the responder)
and `z_client` second (Z of the initiator) — opposite of the spec.**
This is the same `ZA ∥ ZB` order as GmSSL/openHiTLS/Tongsuo. It is
*internally* consistent in the sense that two gm-tlcp instances would
agree, but it deviates from the spec text.

**PMS computation — server-side (M-2 in our internal audit):**

```rust
// src/tlcp/mod.rs:2419-2444 (default mode, raw 32-byte ECDH; PR-A fix at
// src/tlcp/mod.rs::accept_with_certs step 8 + src/tlcp/cv_helper.rs).
#[cfg(not(feature = "tlcp-strict"))]
let pms = match server_ephemeral_kp_opt {
    Some(kp) => kp.compute_shared_secret(peer_pub) ...,
    ...
};
```

**Default mode** uses `Sm2EcdhKeypair::compute_shared_secret(peer_pub)` from
`gm-crypto/src/sm2.rs:1076`, which is **plain standard ECDH**:

```c
shared_point = ProjectivePoint::from(*peer_pk.as_affine()) * self.scalar;
return shared_point.to_affine().to_encoded_point(false).x().to_vec();   // 32 bytes
```

No x̂ transform, no Z values, no KDF, no SM2 specific anything. Returns
the **32-byte x-coordinate of `peer_pub * self_priv`** and feeds that
straight into PRF as the "PMS". Preserved for byte-for-byte compatibility
with the existing GmSSL interop tests (which never actually exercised
the server-side ECDHE PMS path because the interop tests are
`#[ignore]`-d in CI).

**Strict mode** (`--features tlcp-strict`) — fixed by PR-A:

```rust
#[cfg(feature = "tlcp-strict")]
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
```

produces the spec-conformant 48-byte KDF PMS with the same `(z_server,
z_client)` argument order as the client. The server obtains `client_enc_xy`
by parsing the client's first Certificate message (sent in reply to the
server's new CertificateRequest, which PR-A also adds).

**Note:** the in-source comments in this crate (e.g. `"matches GmSSL master"`)
are empirical observations, not spec compliance claims. The status column
in §3.1 is the audited fact.

**CKE wire format (default mode, GmSSL-compatible):**

```rust
// src/tlcp/messages/client_key_exchange.rs:107-128
// Body = u16 payload_len || payload
// payload = TLCP_ECH_PARAMS_PREFIX (3 bytes) || pub_len (1 byte) || pub (65 bytes)
```

The gm-tlcp default-mode CKE body is `u16(0x0045 = 69) || 03 00 29 || 41 || pub`; the complete body is 71 bytes including the two-byte prefix.
The outer `u16` matches GmSSL master; openHiTLS and Tongsuo omit the outer u16 prefix on the ECDHE CKE path.
The inner `TLCP_ECH_PARAMS_PREFIX = [0x03, 0x00, 0x29]` is the
ECParameters envelope (curve_type=0x03, named_curve=u16 0x0029, then
`pub_len` u8 then pub).

**CKE wire format (strict mode, openHiTLS-compatible):** No u16 prefix.
Body = `03 00 29 || pub_len || pub`. Matches openHiTLS's
`PackDtlcpbytes` output.

**Note on the ECParameters envelope itself:** All four implementations
encode it identically as `0x03 || 0x00 || 0x29` (u8 curve_type 0x03
followed by u16 named_curve 0x0029). Tongsuo splits the u16 named_curve
into two consecutive `WPACKET_put_bytes_u8` calls, producing the same
bytes; the other three write it as one u16. gm-tlcp default and strict
modes differ only in the outer CKE u16 prefix, not in the ECParameters
envelope. The PR3-1 fix was cfg-gated to allow interoperation with both
GmSSL (which adds the outer u16) and openHiTLS/Tongsuo (which do not).

**Signature algorithms extension:** Not present in gm-tlcp's
ClientHello. TLCP §6.4.5.2.1 (ClientHello fields) does not list
`signature_algorithms` as a required extension (the national standard
fixes on SM2-with-SM3 only). So omission is fine.

**PRF:** `PRF(secret, label, seed) = HMAC-SM3(secret, ...)` per
`src/tlcp/key_material.rs`. Standard 48-byte master secret derivation
per RFC 5246 / spec. **Matches.**

**Record layer:** `SM4-CBC` with HMAC-SM3 (per `key_material.rs` PRF
expansion); `SM4-GCM` with AEAD (per cipher suite dispatch).

**Finished message:** `PRF(master_secret, "client finished",
MD5+SHA1_hash(handshake_messages))` for legacy; TLCP uses
`PRF(master_secret, "client finished", SM3_hash(handshake_messages))`.
Verified in `messages/finished.rs`. **Matches spec.**

**Session ID handling:** `MaxLen = 32` bytes (`constants.rs`); zero-length
allowed; `legacy_session_id_echo` honored in ServerHello. **Matches spec.**

**GMT Unix time in `random[0..4]`:** Implemented (`constants.rs::current_gmt_unix_time`,
applied in `handshake/server.rs::new` and `with_session_cache`). The
standard defines `Random = gmt_unix_time (uint32) || random_bytes[28]`
in §6.4.5.2.1. **Matches.**

**CertVerify signature:** SM2-with-SM3 over
`ClientHello.random || ServerHello.random || handshake_messages`.
Verified in `crypto/verify.rs`. **Matches spec §6.4.6.**

**Compression methods:** Only `null(0)`. **Matches spec.**

**Padding strategy (CBC-mode suites):** TLS 1.2-style padding (the spec
inherits this from RFC 5246 §6.2.3.2). **Matches.**

**Triple Handshake / Renegotiation:** Not implemented. Per the Springer
2026 paper (Section "Recommendations"), TLCP is structurally vulnerable
to the triple handshake attack and should disable renegotiation or use
PSK. None of the four implementations address this.

---

## 3. Cross-implementation comparison

### 3.1 Matrix of spec coverage

Legend: ✓ implemented, △ partial / gated, ✗ not implemented, — not
applicable.

| Spec feature | Spec | GmSSL master | openHiTLS | Tongsuo | gm-tlcp 0.2.0 |
| --- | --- | --- | --- | --- | --- |
| Protocol version 0x0101 | ✓ | ✓ | ✓ | ✓ | ✓ |
| Dual-cert (sign + enc) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ECDHE_SM4_CBC_SM3 (0xE011) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ECC_SM4_CBC_SM3 (0xE013) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ECDHE_SM4_GCM_SM3 (0xE051) | ✓ | ✓ | ✓ | ✓ | ✓ |
| ECC_SM4_GCM_SM3 (0xE053) | ✓ | ✓ | ✓ | ✓ | ✓ |
| IBSDH_SM4_CBC_SM3 (0xE015) | ✓ | ✗ | ✗ | △ (declared, no SM9 code) | ✗ |
| IBSDH_SM4_GCM_SM3 (0xE055) | ✓ | ✗ | ✗ | △ | ✗ |
| IBC_SM4_CBC_SM3 (0xE017) | ✓ | ✗ (comment only) | ✗ | △ | ✗ |
| IBC_SM4_GCM_SM3 (0xE057) | ✓ | ✗ | ✗ | △ | ✗ |
| RSA_SM4_CBC_SM3 (0xE019) | △ (predecessor only) | ✗ | ✗ | ✓ | ✗ |
| RSA_SM4_GCM_SM3 (0xE059) | △ | ✗ | ✗ | ✓ | ✗ |
| RSA_SM4_CBC_SHA256 (0xE01C) | ✓ | ✗ | ✗ | ✓ | ✗ |
| RSA_SM4_GCM_SHA256 (0xE05A) | ✓ | ✗ | ✗ | ✓ | ✗ |
| Session resumption / abbreviated HS | ✓ | ✗ | ✓ (via generic TLS 1.2) | ✓ (via generic) | △ (struct only) |
| `signature_algorithms` extension | △ (not required by spec) | ✗ | ✓ | ✓ | ✗ |
| GMT Unix time in ClientHello.random[0..4] | ✓ | — | — | — | ✓ |
| `client_version` in ECC-suite PMS | ✓ | ✓ | ✓ | ✓ | — (covered in spec's ECC path) |
| x̂ transform in t (own ephemeral) | ✓ | ✓ | ✓ | ✓ | ✓ |
| x̂ transform in shared point (peer ephemeral) | ✓ | ✓ | ✓ | ✓ | ✓ |
| KDF input `xV ∥ yV ∥ ZA ∥ ZB` | ✓ | ✓ | ✓ | ✓ | ✓ (client call-site); server does not call this function |
| ECC-suite SM2-encrypt PMS to enc pub | ✓ | ✓ | ✓ | ✓ | △ (explicit error path) |
| Finished = `PRF(MS, label, SM3(transcript))` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `client_version` byte in Finished transcript | ✓ | ✓ | ✓ | ✓ | ✓ |
| Renegotiation / triple handshake protection | ✗ (structurally vulnerable) | ✗ | ✗ | ✗ | ✗ |

### 3.2 Cipher-suite wire-format deviations

**Inner ECDHE parameters envelope** (the ECParameters-wrapped ephemeral
public key) is identical across all four implementations:

```
curve_type  (u8)        = 0x03              // named_curve
named_curve (u16, big endian) = 0x0029      // sm2p256v1
pubkey_len  (u8)        = 0x41              // 65
pubkey      (65 bytes)  = uncompressed SM2 point (04 || x || y)
signature_len (u16, big endian)
signature   (variable, ~64 bytes for SM2-with-SM3)
```

Verified at the byte level for each implementation:
- **GmSSL master** (`src/tls.c:tls_server_ecdh_params_to_bytes`):
  `tls_uint8_to_bytes(curve_type) + tls_uint16_to_bytes(named_curve) +
  tls_uint8array_to_bytes(point)`. The 69-byte `client_ecdh_params`
  buffer is the standard layout.
- **openHiTLS** (`tls/handshake/pack/src/pack_client_key_exchange.c:
  PackDtlcpbytes`): `PackAppendUint8ToBuf(HITLS_EC_CURVE_TYPE_NAMED_CURVE) +
  PackAppendUint16ToBuf(HITLS_EC_GROUP_SM2)`. Same 3-byte prefix.
  `GetNamedCurveMsgLen` confirms: `Curve type (1 byte) + Curve ID (2 byte) +
  Public key length (1 byte) + Public key + Signature length (2 byte) +
  Signature`.
- **Tongsuo** (`ssl/statem_ntls/statem_ntls_clnt.c:467`): three
  `WPACKET_put_bytes_u8` calls — the wire bytes are
  `curve_type (u8) || 0 (u8) || curve_id (u8)`, identical to the
  u16-named-curve layout (the `|| 0 || curve_id` is the big-endian u16
  0x0029 split into two u8 writes).
- **gm-tlcp** (`src/tlcp/constants.rs`): `TLCP_ECH_PARAMS_PREFIX =
  [TLCP_EC_CURVE_TYPE_NAMED_CURVE, TLCP_NAMED_CURVE_SM2P256V1[0],
  TLCP_NAMED_CURVE_SM2P256V1[1]] = [0x03, 0x00, 0x29]`.

All four implementations agree on the inner ECDH parameters envelope.

**Outer CKE body framing** differs — and is the source of the PR3-1 fix:

| Suite | Spec | GmSSL | openHiTLS | Tongsuo | gm-tlcp default | gm-tlcp strict |
| --- | --- | --- | --- | --- | --- | --- |
| ECDHE CKE body | none (HS hdr) | **u16** prefix | no prefix | no prefix | **u16** prefix | no prefix |
| ECC CKE body | none (HS hdr) | **u16** prefix | **u16** prefix | **u16** prefix | **u16** prefix | no prefix |

Verification:
- **GmSSL master** always wraps both ECDHE and ECC CKE with
  `tls_uint16array_to_bytes(enced_pms, ...)` (line 339, `src/tlcp.c`).
- **openHiTLS** has `PackStartLengthField(pkt, sizeof(uint16_t), ...)`
  in `PackClientKxMsgEcc` (line 220, `pack_client_key_exchange.c`) but
  `PackClientKxMsgNamedCurve` (line 60) for ECDHE does **not** add an
  outer u16 prefix — it only writes the ECParameters envelope
  directly.
- **Tongsuo** has `WPACKET_sub_reserve_bytes_u16` + `..._u16` for the
  ECC suite (`ntls_construct_cke_sm2`, lines 587/625) but `ntls_construct
  _cke_sm2dhe` for ECDHE writes the envelope directly with no outer
  u16 prefix. The author was aware of this and left a comment:
  > "The standard TLS protocol requires no u16 len bytes before the
  > encrypted PMS value. The NTLS specification is also very blurry on
  > this. But major implementations require the 2 bytes length field
  > (which is redundant), otherwise handshake will fail."
- **gm-tlcp default** wraps everything with u16 (line 121 of
  `client_key_exchange.rs`); **gm-tlcp strict** skips it (line 124,
  same file). This is exactly the PR3-1 fix.

The gm-tlcp default mode therefore emits a u16 prefix for the ECDHE
CKE body, which is what the `// matches GmSSL 2026-06+ master`
comment claims. openHiTLS's ECDHE CKE does **not** have that prefix, so
gm-tlcp default-mode ↔ openHiTLS ECDHE interop fails at CKE parse
time, which is what PR3-1 documented and fixed.

**Other elements:**

| Element | All four implementations |
| --- | --- |
| SKE sig (ECDHE) over | `client_random ‖ server_random ‖ server_ecdh_params` |
| SKE sig (ECC) over | Three interpretations coexist in the ecosystem: (A) skip SKE entirely per RFC 5246 §7.4.3; (B) `client_random ‖ server_random ‖ enc_cert` (sig-only body — openHiTLS / Tongsuo); (C) ECDHE-style body `client_random ‖ server_random ‖ server_ecdh_params` (GmSSL master 2026-09+ and gm-tlcp default mode). gm-tlcp `tlcp-strict` mode implements (A); gm-tlcp default mode implements (C). See `AUDIT-2026-09-06-v2.md §C-2` for the full three-interpretation analysis. |
| CKE sig | n/a |
| SKE envelope (ECDHE) | `ECParameters` (3 bytes: u8 curve_type + u16 named_curve) ‖ u8 pub_len ‖ pubkey ‖ u16 sig_len ‖ sig |

Note on ECC SKE: three interpretations coexist (see §3.2 row above).
GmSSL master actually emits ECDHE-style body for static-ECC too
(re-checked 2026-09-07 against `Guanzhi/GmSSL` HEAD `a8f4d3b`); the
earlier claim that GmSSL emits sig-only over `enc_cert` was wrong.
openHiTLS / Tongsuo emit sig-only over `enc_cert`; gm-tlcp strict mode
**skips** SKE per RFC 5246 §7.4.3; gm-tlcp default mode emits
ECDHE-style (matches GmSSL master). The body shapes therefore disagree
in three different ways across the four implementations. Practical
impact: gm-tlcp ↔ GmSSL master static-ECC interop works in both
directions (both ECDHE-style); gm-tlcp ↔ openHiTLS / Tongsuo static-ECC
interop fails in both directions in both modes. Fixing openHiTLS /
Tongsuo static-ECC interop requires implementing interpretation (B)
in gm-tlcp and is deferred (couples with C-4 server-side CKE
decryption; see `AUDIT-2026-09-06-v2.md §C-2`).

### 3.3 Crypto-algorithm deviations from spec

For all four implementations, the **ECDHE PMS KDF input order** is
`xV ∥ yV ∥ ZA ∥ ZB`, which is exactly the spec-mandated order. The
non-deviation is the same in all four implementations, which is one
reason pairwise interop within this cluster is plausible.

| Implementation | t = x̂(own_R.x)·r + d | shared = peer_R · x̂(peer_R.x) + peer_P | KDF order |
| --- | --- | --- | --- |
| **GB/T 32918.3-2016** | ✓ | ✓ | `xV ∥ yV ∥ ZA ∥ ZB` |
| GmSSL master | ✓ | ✓ | `xV ∥ yV ∥ ZA ∥ ZB` |
| openHiTLS | ✓ | ✓ | `xV ∥ yV ∥ ZA ∥ ZB` |
| Tongsuo | ✓ | ✓ | `xV ∥ yV ∥ ZA ∥ ZB` |
| gm-tlcp (`pms.rs` formula) | ✓ | ✓ | (formula correct, depends on call-site order) |
| gm-tlcp client call-site | ✓ (uses `local_x_hat`) | ✓ (uses `peer_x_hat`) | passes `(z_server, z_client)` = (ZA, ZB) → KDF = `xV ∥ yV ∥ ZA ∥ ZB` |
| gm-tlcp server | uses raw `compute_shared_secret` (standard ECDH, 32 bytes x-coord, no x̂, no KDF, no Z) | — | — |

The **gm-tlcp server is the only one of the four that does not even
attempt the spec formula**. It uses standard ECDH, which produces a
different length *and* different content than any of the others.
Fixing the server to use `compute_tlcp_ecdhe_pms` is the only way to
make gm-tlcp interop with any spec-conformant peer — or, equivalently,
to interop with itself (client ↔ server).

### 3.4 Interop status as of gm-tlcp 0.2.0

The CI's "gm-tlcp × GmSSL TLCP Interop" job reports `11 passed; 0 failed`,
but all 7 actual interop tests in `gm-tlcp/tests/gmssl_interop.rs` are
`#[ignore]`-d behind `gmssl_present()`. The runner image doesn't ship
`gmssl`, so every real interop test prints `"gmssl not on PATH; skipping"`
and returns `Ok(())`. The "11 passed" comes from the *support* unit
tests (`hmac_sm3_*`, `pbkdf2_sm3_basic`, etc.), not from handshake
exchanges.

So the CI green is structurally uninformative about TLCP interop.
Confirmed by reading the test file and the most recent run log.

The only real interop evidence we have is the openHiTLS PR4 strict-mode
e011 (ECDHE_SM4_CBC_SM3) test, run manually, which fails with
`Decrypt Error (51)` on the Finished record. Default-mode interop with
GmSSL master is **structurally untested** in CI: all 7 GmSSL handshakes in
`tests/gmssl_interop.rs` are `#[ignore]`-d and self-skip when the
`gmssl` binary is absent, so CI green is not positive GmSSL interop
evidence. Given the table above, this is consistent with two
distinct root causes (and we cannot tell which is dominant without
fixing each in turn and re-testing):

1. **Server algorithm mismatch**: gm-tlcp's server computes a 32-byte
   raw ECDH x-coord as PMS; openHiTLS computes a 48-byte KDF output as
   PMS. They cannot agree on master_secret regardless of Z order.
2. **ECDHE CKE outer-u16 mismatch in default mode**: gm-tlcp
   default-mode emits `u16(0x0045) || 03 00 29 || 41 || pub`, while
   openHiTLS expects the ECParameters envelope directly with no outer
   u16 prefix. The PR3-1 fix was cfg-gated on `tlcp-strict` for exactly
   this reason.

### 3.5 Best-fit ranking against the spec text

If we rank purely on spec conformance (ignoring the interop cluster):

1. **openHiTLS** — closest. CKE wire format matches spec exactly
   (no outer u16 prefix on the ECDHE CKE body, ECParameters is a u16
   named_curve). Server uses the spec formula. The KDF order is the
   spec-conformant `ZA ∥ ZB`. Static-ECC SKE uses interpretation B
   (signature-only over `cr ∥ sr ∥ enc_cert`).
2. **Tongsuo** — second-closest. PMS formula matches spec. RSA
   suites are wired up. The encrypted static-ECC / RSA CKE body has a
   spec-deviating outer u16 prefix; the ECDHE CKE body has none.
   KDF order is spec-conformant. Static-ECC SKE uses interpretation B.
3. **gm-tlcp 0.3.1** (post-R-2, 2026-09-08) — tied with openHiTLS on
   the ECDHE wire-format axis: default mode emits the spec-conformant
   CKE body (no u16 prefix), the server uses SM2 KAP (48-byte KDF,
   spec-conformant), and both static-ECC and ECDHE suites emit a
   spec-conformant SKE (interpretation-B sig-only body for
   static-ECC). This means the gm-tlcp **client** can complete a
   static-ECC handshake against openHiTLS / Tongsuo 8.3.0 E013
   server up to the server-PMS step. Server-side static-ECC PMS
   decryption (`ECCEncryptedPreMasterSecret`) is pending R-3 /
   gm-tlcp 0.4.0. Server-side RSA suites are pending R-5 / 0.6.0.
   See `AUDIT-2026-09-06-v2.md` for the updated post-0.3.1
   critical-finding tally.
4. **GmSSL master** — wire-format deviation on the ECDHE CKE body
   (outer u16 prefix; same as gm-tlcp ≤ 0.2.x default). KDF order is
   spec-conformant. Static-ECC SKE uses interpretation C (ECDHE-style
   SKE body, not sig-only). Smaller code base, fewer features, but
   the parts that exist match spec.
5. **gm-tlcp 0.2.0** — historical, superseded by 0.3.0 and 0.3.1.
   Listed here only for reference: the server still uses raw
   `compute_shared_secret` (32-byte x-coordinate), which is a
   fundamentally different algorithm from the spec's SM2 KAP, and
   default mode emits the u16 CKE prefix. See
   [gm-tlcp-v0.2.2](https://github.com/GM-Engineers/gm/compare/gm-tlcp-v0.2.2...gm-tlcp-v0.3.1)
   for the diff that fixed both.

### 3.6 Findings and (non-binding) follow-up

The analysis above identifies one substantive defect in gm-tlcp:

1. **Server-side algorithm fix (recommended)**: the server must call
   `compute_tlcp_ecdhe_pms(...)` instead of
   `kp.compute_shared_secret(...)`. Inputs needed: client's enc pub
   (already in scope from `process_server_certs`), client's ephemeral
   pub (from CKE), server's enc priv/pub (already in scope),
   `z_server`/`z_client` (need to be made available at this site). The
   argument order at the server call site must be `(z_server,
   z_client)` to match the client; do not introduce a mixed-order
   half-fix, since that would make the two sides derive different PMS
   values. Cfg-gate behind `--features tlcp-strict` is a reasonable
   way to keep default-mode behavior stable until positive GmSSL
   interop is observed.

3. **Cross-implementation interop test** (new). Add an end-to-end
   TlcpConnector ↔ TlcpAcceptor test that runs a full handshake on a
   `tokio::TcpStream` and asserts both reach `AppData`. This does
   **not** require the gmssl binary and is the missing test that would
   have caught the server-side bug earlier.

2. **Cross-implementation interop test (recommended)**: add an end-to-end
   TlcpConnector ↔ TlcpAcceptor test on a `tokio::TcpStream` that asserts
   both sides reach `AppData`. This does not require the gmssl binary and
   is the missing test that would have caught the server-side bug earlier.

3. **Update M2-ROOT-CAUSE-ANALYSIS.md** to remove the now-incorrect
   client Z-order claim and the mixed-order fix proposal, and to state
   that the substantive defect is the server algorithm.

---

## 4. Summary in one paragraph

GmSSL master, openHiTLS, and Tongsuo are all "partial TLCP" — each
implements a narrow subset (predominantly ECDHE+ECC × CBC+GCM, SM2-based)
of the GB/T 38636-2020 cipher suite table; none of them implements SM9
IBC/IBSDH at the code level, and Tongsuo is the only one that actively
wires up the four RSA suites. All four implementations use the
spec-conformant ECDHE KDF input order `xV ∥ yV ∥ ZA ∥ ZB` (server=A,
client=B), and three of them encode the ECDHE CKE body as
`03 00 29 || pub_len || pub`; GmSSL master wraps that in an extra u16
prefix. gm-tlcp's `pms.rs` formula is spec-correct and the client call
site already uses the spec-conformant `(z_server, z_client)` argument
order. The only confirmed defect in gm-tlcp is that the server still
uses raw `compute_shared_secret` (standard ECDH, 32-byte x-coord)
instead of `compute_tlcp_ecdhe_pms` (48-byte KDF output), so the
client and server produce different PMS values and can never agree on
the master secret. Fixing that single call site is the only change
required to make gm-tlcp interop with any spec-conformant peer.

---

## 5. Sources

- `gm/gm-tlcp/src/tlcp/pms.rs` — formula audited in PR4/5
- `gm/gm-tlcp/src/tlcp/mod.rs` — call sites audited in PR4
- `gm/gm-tlcp/interop/M2-ROOT-CAUSE-ANALYSIS.md` — prior analysis; this
  document supersedes its client Z-order claim and its mixed-order fix plan
- `gmssl-master/src/tlcp.c` and `src/sm2_exch.c`
- `gmssl-master/include/gmssl/tls.h` — cipher suite constant table
- `openhitls/openhitls/tls/handshake/{pack,send,recv,common}/...`
- `openhitls/openhitls/crypto/sm2/src/sm2_exch.c` and `sm2_sign.c`
- `openhitls/openhitls/include/tls/{hitls_config,cipher_suite}.h`
- `tongsuo/Tongsuo-8.3.0/ssl/statem_ntls/statem_ntls*.c`
- `tongsuo/Tongsuo-8.3.0/crypto/sm2/sm2_kep.c`
- `tongsuo/Tongsuo-8.3.0/include/openssl/ntls.h`
- GM/T 0003.3-2012 PDF (downloaded from gmbz.org.cn, Annex A.2 example
  fully extracted)
- `github.com/xuyang2/ntls-notes` — transcribed GB/T 38636-2020 cipher
  suite table
- `tonybai.com/2022/07/17/...` — GB/T 38636-2020 removed SM1 from
  GM/T 0024-2014. TonyBai's claim that RSA suites were also removed is
  contradicted by GB/T 38636-2020 §6.4.5.2.1 表 2 itself, by the
  independent transcriptions (`xuyang2/ntls-notes`, `Trisia/gotlcp`),
  and by Tongsuo's `ntls.h` constants; treat the article as authoritative
  only for the SM1 removal.
- `/Users/laozhang/Downloads/GBT+38636-2020.pdf` — the national standard
  itself. The 表 2 cipher-suite table is in §6.4.5.2.1; SKE structure in
  §6.4.5.4; CKE structure in §6.4.5.8; CertificateVerify in §6.4.5.9;
  Finished in §6.4.5.10; master_secret in §6.5.1; key_block in §6.5.2.
- `GM/T 0003.3-2012 §6.1 + Annex A` — the SM2 KAP protocol and KAT
  (`KA = KB = 55B0AC62A6B927BA23703832C853DED4`); cited as the canonical
  reference for the SM2 key-agreement steps A4..A8 / B3..B7.
- `link.springer.com/article/10.1186/s42400-026-00599-y` — academic
  TLCP formal analysis (Jul 2026); identifies 9 attack vectors and
  derives 5 mitigation recommendations, including the triple-handshake
  structural vulnerability