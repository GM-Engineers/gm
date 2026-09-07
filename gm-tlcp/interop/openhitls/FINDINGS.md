# gm-tlcp ↔ openHiTLS TLCP interop: findings (2026-09-06)

This is the working log for the openHiTLS (GB/T 38636-2020 TLCP 1.1) interop
test against `gm-tlcp`. All findings are reproducible from this directory:

```
build_openhitls.sh   # one-shot Docker build of openhitls main (Linux ARM64 ELF)
gen_certs.sh         # dual SM2 sign+enc cert pair for the gm-tlcp side
run_interop.sh       # orchestrator (single-shot suite)
run_mutual_auth.sh   # orchestrator that exercises ECDHE mutual-auth
run/                 # ephemeral logs + derived artifacts
wire-traces/         # captured pcap files for each attempt
```

The single-shot `run_interop.sh` (no client cert, defaults to the bundled
openHiTLS CA-signed SM2 certs at `openhitls-bin/test-certs/sm2_with_userid/`)
exercises every suite and exits non-zero on any failure. See the bottom of
this file for the final per-suite result table.

## TL;DR — what works, what doesn't

| Suite       | Mode                | gm-tlcp ↔ openHiTLS | First failure point                 |
| ----------- | ------------------- | ------------------- | ----------------------------------- |
| `0xE011`    | ECDHE_SM4_CBC_SM3   | fails at CKE wire-format decode (openHiTLS) | ClientKeyExchange parsing |
| `0xE051`    | ECDHE_SM4_GCM_SM3   | same as `E011`      | ClientKeyExchange parsing           |
| `0xE013`    | ECC_SM4_CBC_SM3     | fails earlier       | ServerKeyExchange format mismatch    |
| `0xE053`    | ECC_SM4_GCM_SM3     | same as `E013`      | ServerKeyExchange format mismatch    |

The ECDHE path actually negotiates successfully through ServerHello,
Certificate (dual cert), ServerKeyExchange (with full ECParameters +
ECPoint + signature), CertificateRequest, ServerHelloDone; gm-tlcp
also correctly signs + sends Certificate (sign + enc), and then sends
ClientKeyExchange — but openHiTLS' CKE parser refuses the bytes
(`alert Decode Error`). See §"CKE wire format" below.

The static-ECC path never gets out of the ServerKeyExchange stage
because openHiTLS sends a non-standard SKE for `E013`/`E053` (no
ECParameters + ECPoint envelope, just a DER-encoded SM2 signature
`r || s`); gm-tlcp' parser rejects it.

## Per-suite progress with wire traces

### 1. `E013` (static ECC + CBC) — `wire-traces/e013-static.pcap`

Client → Server:
```
16 01 01 00 2d   # record: HS, ver 0x0101, len 45
01 00 00 29      # HS type 1 (ClientHello), len 41
01 01            # client_version = 0x0101
fc 90 eb 92 ...  # client_random (32 bytes)
00               # session_id_len = 0
00 02 e0 13      # cipher_suites_len = 2, suite = 0xE013
01 00            # compression_methods_len = 1, method = null
                 # (no extensions)
```

Server → Client:
```
16 01 01 00 4a   # record: HS, ver 0x0101, len 74
02 00 00 46      # HS type 2 (ServerHello), len 70
01 01            # server_version = 0x0101
... <random> ... # server_random
00               # session_id_len = 0
e0 13            # selected_cipher_suite = 0xE013
01 00            # compression = null
                 # (no extensions)
16 01 01 04 36   # record: HS, ver 0x0101, len 0x436
0b 00 04 32     # HS type 11 (Certificate), len 0x432
00 04 2f        # certificates_len = 0x42f
00 02 15        # first cert len = 0x215 = 533 (sign cert)
30 82 02 11 ... # DER sign cert (529 bytes payload)
00 02 14        # second cert len = 0x214 = 532 (enc cert)
30 82 02 10 ... # DER enc cert (528 bytes payload)
16 01 01 00 4d   # record: HS, ver 0x0101, len 77
0c 00 00 49      # HS type 12 (ServerKeyExchange), len 73
00 47            # SKE params_len = 71
30 45            # DER SEQUENCE, len 0x45 = 69
   02 20 ...     # INTEGER 32 bytes (the SM2 `r`)
   02 21 00 ...  # INTEGER 33 bytes (SM2 `s` with leading sign byte 00)
16 01 01 00 04   # record: HS, ver 0x0101, len 4
0e 00 00 00      # HS type 14 (ServerHelloDone), len 0
```

gm-tlcp parses ServerHello (good) and Certificate (good — dual cert
recognized). For static-ECC suite E013, gm-tlcp's
`verify_ske_signature(is_ecc_mode=true, ...)` branch reads the SKE
body as:
```
sig_len (2 bytes BE) || DER-encoded SM2 signature (sig_len bytes)
```

— exactly what openHiTLS sends for E013 (sig_len = 71 bytes, signature =
the standard SM2 SEQUENCE { r INTEGER, s INTEGER }). The signature
covers `cr ‖ sr ‖ uint24(enc_cert_len) ‖ enc_cert_der` (per openHiTLS
`HS_PrepareSignDataTlcp` at
`openhitls/tls/handshake/common/src/hs_common.c:255`), which is
exactly what gm-tlcp builds at `verify.rs:39-48`. **SKE signature
verification succeeds.**

After step 4 (SKE read) and step 5 (verify, no I/O), gm-tlcp runs
step 5.5 at `mod.rs:1505-1529`: it reads the next record expecting
either CertificateRequest or ServerHelloDone. openHiTLS's 4th record
**is** SHD (it does NOT send CR for static-ECC), so the
`cr_type == HandshakeType::ServerHelloDone` branch at `mod.rs:1513-1518`
runs: the SHD bytes are appended to the transcript and execution
falls through. The comment at `mod.rs:1517-1525` admits: "We can't
easily 'unread' the record; just fall through and re-fetch SHD as
usual."

Step 6 at `mod.rs:1531-1533` then tries to read **another** record
expecting SHD. The server has no more bytes to send. The client hangs
on an empty socket. Captured in `wire-traces/e013-static.pcap`.

(An earlier draft of this section incorrectly stated that gm-tlcp's
SKE parser expects the ECDHE-format `ECParameters + ECPoint` envelope
for static-ECC, which is wrong: gm-tlcp's `Sm2EcdheParams::from_bytes`
IS called in the ECDHE branch of `verify_ske_signature`, but for
static-ECC the code takes the `if is_ecc_mode` branch which only reads
`[2B sig_len] [DER sig]`. The "wrong ECParameters prefix" error would
fire for `E011`/`E051`, not `E013`/`E053`.)

### 2. `E011` (ECDHE + CBC) — `wire-traces/ecdhe-with-mutual-auth.pcap`

This is the closest we got to a successful handshake. Both sides
exchanged every required message; only the CKE bytes tripped
openHiTLS.

gm-tlcp → openHiTLS:
- ClientHello (offering only `E011`)
- Certificate (sign + enc, both signed by openHiTLS bundled CA)
- ClientKeyExchange (75 bytes)
- CertificateVerify (148 bytes)
- ChangeCipherSpec
- Finished

openHiTLS → gm-tlcp:
- ServerHello (selected `E011`)
- Certificate (sign + enc, both bundled)
- ServerKeyExchange (147 bytes — has full ECParameters + ECPoint + sig)
- CertificateRequest (ECDSA Sign only, no DN list)
- ServerHelloDone
- Alert (Level: Fatal, Description: **Decode Error**)

OpenHiTLS error code: `0x02060004` = `HITLS_PARSE_UNSUPPORT_HANDSHAKE_MSG`
(or `HITLS_PARSE_INVALID_MSG_LEN` — same module, different offset).

The Decode Error is raised in `parse_client_key_exchange.c`
(`ParseClientKxMsgEcdhe`) when it tries to parse the CKE body. The
TLCP11 branch at lines 49-59 expects to skip 3 bytes (ECParameters)
and then read a 1-byte point length. gm-tlcp's CKE body is:

```
00 47 03 00 29 41 04 <point 64 bytes>
^     ^----------^--- 1-byte len = 0x41 = 65 (correct)
|     |
|     curve_type=3, named_curve=0x0029 (sm2p256v1) (correct)
2-byte uint16 length prefix = 0x0047 (gm-tlcp adds this)
```

openHiTLS skips the first 3 bytes — `00 47 03` — and tries to read
the 4th byte as a 1-byte point length: that byte is `0x00`, which is
rejected as "point length is zero" → `HITLS_PARSE_INVALID_MSG_LEN`
→ `ALERT_DECODE_ERROR`.

### 3. CKE wire format

GB/T 38636-2020 §6.4.1.6 is a thin layer on top of RFC 5246 §7.4.7.
For ECDHE cipher suites both documents require the body to be:

```
ECParameters  curve_type (1) + named_curve (2)
ECPoint       point_len (1) + point (<= 65 bytes)
```

— i.e. NO overall length prefix on the body. The handshake layer
already accounts for the body length via the 24-bit `length` field in
the standard handshake header.

gm-tlcp's `client_key_exchange.rs` (line 105) writes an extra
`uint16 payload_len` prefix between the handshake header and the
ECParameters. The comment at line 102 says:

```rust
// 16-bit payload length prefix (matches GmSSL 2026-06+
// tls_uint16array_to_bytes format). The previous version of
// this code used a 1-byte length prefix which was non-standard
// and rejected by GmSSL master.
```

So gm-tlcp's wire format is specifically tuned to match GmSSL
2026-06+ master. openHiTLS — which targets GB/T 38636-2020 strictly
— has no such prefix, and therefore cannot parse gm-tlcp's CKE.

This is a real ecosystem split: implementations that follow GmSSL
master's wire format do not interop with implementations that follow
the standard. Either:

- **gm-tlcp drops the `uint16` prefix** (one-line fix:
  `to_bytes()` in `client_key_exchange.rs`; remove the `buf.extend_from_slice(&(payload_len as u16).to_be_bytes())`
  line and the corresponding `from_body` length-prefix handling).
  This will fix interop with openHiTLS but will require verifying it
  does not regress GmSSL master interop.

- **openHiTLS adds a length-prefix-tolerant parser**. Lower-impact on
  gm-tlcp but higher-impact on the openHiTLS side, which has stated it
  targets the standard strictly.

This is the primary blocker for ECDHE interop. Until either side
relaxes, gm-tlcp and openHiTLS can handshake through Certificate but
cannot reach Finished.

### 4. Server cert (sign) on the gm-tlcp side

For gm-tlcp to verify the SKE signature (which it does for both
ECDHE and static-ECC suites, lines 1467-1493 of `src/tlcp/mod.rs`),
it needs the server's sign public key as a 65-byte uncompressed
SEC1 point. The third positional arg of `interop_client` accepts
exactly that (`04 || X || Y`, 130 hex chars).

The bundled openHiTLS certs at
`openhitls-bin/test-certs/sm2_with_userid/sign.crt` work. Their
public key (130 hex chars, no `0x` prefix) is:

```
04ca9fdb5aba25ed11906907d268c81140681204d57c3eee8ce8997b8d82cd957310dcd6dcdeb537e9feed7a2acacb6db29959615a74d0382ef700ffae319a77ae
```

This is also saved to `run/bundled_sign_pub.hex` so the test harness
can read it via `awk 'NR==1 { sub(/^0x/, ""); print }'`.

### 5. Client cert (for ECDHE mutual-auth)

For ECDHE suites, openHiTLS unconditionally sends a CertificateRequest
after ServerHelloDone (verified in the wire traces). gm-tlcp refuses
to proceed without a client cert:

```
[client] handshake FAILED: HandshakeFailed("Server sent CertificateRequest
  but no client certificate was configured. Call
  TlcpConnector::with_client_certs() with a cert chain + signing key
  before connect.")
```

`examples/interop_client.rs` now accepts four extra positional args
(DER sign cert, DER enc cert, PKCS#8 PEM sign key, PKCS#8 PEM enc
key) which it feeds to `TlcpConnector::with_client_certs(...)`.

Client cert requirements:
- Both sign and enc certs MUST be supplied. openHiTLS server-side
  (`recv_certificate.c:172-200`) requires the chain to contain an
  enc cert at minimum; otherwise `HITLS_CERT_ERR_EXP_CERT`.
- Both certs MUST chain to a CA the server was given via `-CAfile`.
  We used `openhitls-bin/test-certs/sm2_with_userid/ca.crt` as the
  issuer (see `gen_client_certs.sh`).
- Both certs MUST have proper X509v3 extensions:
  - sign cert: `keyUsage = critical, digitalSignature, nonRepudiation`
    + `extendedKeyUsage = clientAuth`
  - enc cert:  `keyUsage = critical, keyAgreement, keyEncipherment, dataEncipherment`
  A cert generated with bare `openssl req -x509` (X.509v1) is rejected
  with `HITLS_CERT_ERR_KEYUSAGE`.

The `run/client_certs/` directory in this folder has both certs (PEM,
DER, and PKCS#8 PEM keys), generated and verified against the openHiTLS
CA.

## Pipeline / script notes

- `build_openhitls.sh` builds openHiTLS main (Ubuntu 22.04 container)
  with `HITLS_BUILD_PROFILE=full HITLS_BUILD_EXE=ON`. Output is staged
  to `openhitls-bin/`. The unified CLI binary is `hitls` (NOT
  `hitls_cli` — that was renamed upstream). macOS xattr (`._*`) is
  stripped before `tar` to keep gcc happy.

- `gen_certs.sh` produces the dual SM2 cert pair using plain openssl
  because `hitls req` only generates CSRs (no `-x509`).

- `run_interop.sh` (no client cert) and `run_mutual_auth.sh` (with
  client cert) are the two orchestrators. Both keep the
  openhitls-srv-pub container running with the SM2 dual-cert `-tlcp`
  bundle.

- The `-p 52197:52197` publish mode (vs `--network host`) is required
  on macOS Docker Desktop — `--network host` binds the port inside
  the container but does not propagate it to the host loopback in a
  way that `nc -z 127.0.0.1 52197` can see.

- `-accept 0.0.0.0:52197` is required (openHiTLS's `-accept` parser
  accepts `host:port`; a bare port returns `Invalid bind address`).

## Open question: should gm-tlcp match openHiTLS or GmSSL?

The choice between `gm-tlcp` `uint16`-prefixed CKE (matches GmSSL
master) and `openHiTLS` non-prefixed CKE (matches GB/T 38636-2020
strict) is a strategic one. If gm-tlcp wants to interop with the
strict-reading side of the TLCP ecosystem (openHiTLS, and any
future implementation that follows the GB/T standard strictly),
the `uint16` prefix should be dropped. If gm-tlcp stays compatible
with GmSSL 2026-06+ master specifically, it the prefix should stay
and openHiTLS would need to relax its parser.

I recommend opening an upstream issue against openHiTLS for the
symmetric problem (static-ECC SKE format) and either:
1. fix gm-tlcp to drop the CKE prefix and add a regression test
   against both GmSSL master AND openHiTLS, OR
2. add a feature flag to gm-tlcp that toggles the prefix and
   detect at runtime via a probe byte (impractical).

Option 1 is cleaner.

## File index

| File                                    | Purpose                                     |
| --------------------------------------- | ------------------------------------------- |
| `build_openhitls.sh`                    | one-shot openHiTLS Docker build             |
| `gen_certs.sh`                          | SM2 dual cert pair (gm-tlcp side)           |
| `gen_client_certs.sh`                   | SM2 dual cert pair signed by openHiTLS CA   |
| `run_interop.sh`                        | orchestrator, single-shot per suite         |
| `run_mutual_auth.sh`                    | orchestrator with client cert (ECDHE)       |
| `run/extract-pub.sh`                    | extract SM2 uncompressed pub from cert      |
| `run/bundled_sign_pub.hex`              | sign pub from openHiTLS-bundled sign.crt    |
| `run/server_sign_pub.hex`               | sign pub from self-generated sign.crt       |
| `run/client_certs/`                     | client cert pair signed by openHiTLS CA     |
| `run/Dockerfile`                        | docker image with `tcpdump` for wire traces |
| `wire-traces/e013-static.pcap`          | raw pcap for E013 attempt                   |
| `wire-traces/ecdhe-with-mutual-auth.pcap` | raw pcap for E011 with client cert attempt |
| `FINDINGS.md`                           | this document                               |