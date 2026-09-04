# GmSSL — TLCP interop status against gm-tlcp (after 2026-06 fixes)

**GmSSL version tested**: 3.3.0-dev.1183 (current `master` as of 2026-09-02)
**Commit range**: includes the two June 2026 fixes (`57c9433`, `c12edeb`)
**Result**: ✅ handshake completes with the legacy `gmssl_padding_compat = true` shim; ❌ with `gmssl_padding_compat = false` (the "default" path)

## TL;DR

1. The two GmSSL pre-fix bugs we previously identified are real **and are now fixed** in current `master`. No actionable GmSSL bug to file.
2. Our gm-tlcp default `gmssl_padding_compat = false` is the **wrong** default. It is off-by-one against RFC 5246 §6.2.3.2's MAC-then-Encrypt framing (the standard calls for `N` padding bytes + `1` length byte = `N+1` bytes at the tail of the record; we only emit `N`).
3. Our `gmssl_padding_compat = true` shim — which emits `N` bytes of value `N-1` — accidentally lands one byte earlier in the parser and lines up HMAC correctly. This is **why** the PR6 interop test passed against pre-fix GmSSL and still passes against post-fix GmSSL.
4. We should rename / re-document the shim and **flip the default**, then add a regression test that talks to the current `gmssl tlcp_server` to lock the wire format.

## What we verified, against `gmssl tlcp_server` (current `master`)

Built locally on macOS with `cmake -DCMAKE_BUILD_TYPE=Release && make -j8`. Generated SM2 sign + enc certificates via `gmssl sm2keygen` + `gmssl reqgen` + `gmssl reqsign`, all chained under a self-signed `ca_cert.pem`. Combined sign + enc keys into a single PEM file (the binary reads the same key file twice — once for `ctx->x509_keys`, once for `ctx->enc_keys`). Started:

```bash
gmssl tlcp_server -port 52193 \
    -cert server_chain.pem \
    -key server_combined_key.pem -pass P@ssw0rd \
    -cipher_suite TLS_ECC_SM4_CBC_SM3 -verbose
```

Ran gm-tlcp's `interop_client` against it twice (via a local hex-dump proxy on port 52194 to log every byte):

| `GM_TLCP_GMSSL_COMPAT` | Cipher | Server alert | Client outcome |
|---|---|---|---|
| `0` (default) | `TLS_ECC_SM4_CBC_SM3` (0xe013) | `bad_record_mac` (20) | ❌ handshake aborts at server Finished |
| `1` (legacy shim) | `TLS_ECC_SM4_CBC_SM3` (0xe013) | none | ✅ handshake completes, suite = `ECC_SM4_CBC_SM3` |

The same `interop_client` (default settings, `gmssl_padding_compat = false`) has worked against the **bundled** `tests/gmssl_interop.rs` harness since PR6 — that harness runs against the same GmSSL binary, so the question is why the standalone `interop_client` works in the test harness but not here. The answer is: the test harness goes through `TlcpConnector::connect_with_certs` which does **not** exercise the `write_application_data` / MAC-then-Encrypt path. The bug only shows up when we actually use the record layer, which `interop_client` does (it sends an HTTP-style GET after the handshake).

## Root cause analysis (off-by-one in gm-tlcp, not GmSSL)

RFC 5246 §6.2.3.2 (and GB/T 38636-2020 §6.2.3) specifies the MAC-then-Encrypt record as:

```
struct {
    opaque content[TLSCompressed.length];
    opaque MAC[SecurityParameters.mac_key_length];
    uint8 padding[GenericBlockCipher.padding_length];
    uint8 padding_length;
} GenericBlockCipher;
```

That last `uint8 padding_length` is **a separate byte** carrying the value `padding_length`, sitting **after** the array of `padding_length` padding bytes. So the tail of every CBC record is:

```
... || HMAC (32) || <N bytes of value N> || <1 byte of value N>
                                        ↑ last byte
```

This is what GmSSL's `tls_cbc_decrypt` parses (in `src/tls.c`, ~line 480):

```c
padding_len = out[inlen - 1];
padding     = out + inlen - padding_len - 1;   // padding bytes start at inlen - padding_len - 1
if (padding < out + 32) return -1;
for (i = 0; i < padding_len; i++)
    if (padding[i] != padding_len) return -1;

*outlen = inlen - 32 - padding_len - 1;          // outlen = inlen - 33 - padding_len
mac = padding - 32;
```

So `outlen = inlen - 32 - padding_len - 1`, i.e. the **single trailing byte is not counted in `outlen`**.

gm-tlcp's `write_cbc_record` (in `src/tlcp.rs` ~line 2779) currently does:

```rust
let inner_len = plaintext.len() + SM3_HMAC_LENGTH;
let pad_len = SM4_BLOCK_SIZE - (inner_len % SM4_BLOCK_SIZE);
let pad_byte = if self.gmssl_padding_compat {
    (pad_len - 1) as u8          // legacy: N bytes of value N-1
} else {
    pad_len as u8                // "standard": N bytes of value N   ← short by one byte
};
let mut inner = Vec::with_capacity(inner_len + pad_len);
inner.extend_from_slice(plaintext);
inner.extend_from_slice(&hmac);
inner.extend(std::iter::repeat(pad_byte).take(pad_len));
```

So:
- `gmssl_padding_compat = false` produces `inner.len() == plaintext_len + 32 + pad_len` — exactly `N` padding bytes, no length byte. GmSSL parses this with `padding_len = N`, computes `outlen = plaintext_len - 1` and extracts the HMAC one byte too early. The HMAC over the wrong-length plaintext doesn't match the HMAC computed over the actual plaintext → `bad_record_mac`.
- `gmssl_padding_compat = true` produces `N` bytes of value `N-1`. GmSSL reads `padding_len = N-1`, computes `outlen = plaintext_len` and aligns the HMAC correctly. The leftover `1` byte (the last of the `N` bytes of value `N-1`) is silently treated as a phantom "length byte" by GmSSL. That's why the shim works.

The actual fix on our side is:

```rust
let pad_len = SM4_BLOCK_SIZE - (inner_len % SM4_BLOCK_SIZE);  // N
let pad_byte = pad_len as u8;
let total_pad = pad_len + 1;          // N padding bytes + 1 length byte
let mut inner = Vec::with_capacity(inner_len + total_pad);
inner.extend_from_slice(plaintext);
inner.extend_from_slice(&hmac);
inner.extend(std::iter::repeat(pad_byte).take(total_pad));
```

and the symmetric decryption side needs to strip `padding_len + 1` bytes.

## Action items

1. **`gm-tlcp` PR (this repo)**: fix the record-layer MAC-then-Encrypt framing, drop the `gmssl_padding_compat` flag (or rename it), flip the default, update docs. Tests should cover both directions (we as server decrypting GmSSL client; we as client encrypting to GmSSL server).
2. **GmSSL side**: no action. The June 2026 fixes are correct. The only change worth filing there is a **release note** clarifying the wire format and noting that interop peers must follow RFC 5246 §6.2.3.2 (not raw PKCS#7).
3. **CI**: add a `gm-tlcp-tlcp-server-current` job that pulls GmSSL master and runs the round-trip. The existing `gm-tlcp-gmssl-interop` job exercises an older harness; we should switch it to the current `gmssl tlcp_server` binary so we catch any future regression on either side.

## References

- RFC 5246 §6.2.3.2 (TLS 1.2 record-layer MAC-then-Encrypt with explicit `padding_length` byte)
- GB/T 38636-2020 §6.2.3 (TLCP adopts the same MAC-then-Encrypt structure)
- GmSSL commits `57c9433` (2026-06-01) and `c12edeb` (2026-06-13) — both fixes to `sm4_cbc_padding_decrypt`
- GmSSL `src/tls.c:460-490` (the `tls_cbc_decrypt` parser that consumes our records)
- gm-tlcp `src/tlcp.rs:2779` (the buggy `write_cbc_record`)
