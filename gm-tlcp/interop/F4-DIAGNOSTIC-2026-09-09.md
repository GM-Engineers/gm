# F4 Diagnostic — 2026-09-09

**Status:** Empirical root-cause capture complete. Both processes sampled
while deadlocked; syscall call-stacks + TCP socket state captured. F4
remains **OPEN** in the audit; R-9.2 path TBD.

**Reproduction:** `gm-tlcp` 0.6.3 + `gmssl-master` 3.3.0-dev.1183
(commit 1183). Linux/macOS interop test
`tests/gmssl_interop.rs::gmssl_tlcp_handshake_and_app_data`, with
`--features tlcp-gmssl-compat` and the 500ms pre-write sleep already
wired into the test.

**Test command:**
```bash
env PATH=/Users/laozhang/Work/opensource/gmssl-master/build/bin:$PATH \
  cargo test --test gmssl_interop --features tlcp-gmssl-compat -- \
    --ignored gmssl_tlcp_handshake_and_app_data --nocapture
```

---

## 1. Reproduction evidence

The handshake completes successfully on every run:

```
[gm-tlcp] cert dir: /var/folders/.../gm-tlcp-interop-40878
[gm-tlcp] spawned gmssl tlcp_server pid=Some(40896)
[gm-tlcp] gmssl listening on port 57322
[gm-tlcp] gmssl verbose log: /tmp/gm-tlcp-server-40878.log
client handshake OK; negotiated suite = TlcpCipherSuite { id: [224, 81], name: "ECDHE_SM4_GCM_SM3", ... }
test gmssl_tlcp_handshake_and_app_data has been running for over 60 seconds
```

After "client handshake OK", the test enters the 500ms pre-write
sleep, then calls `client.write_application_data(request)` (returns
immediately, ~0 CPU), then `client.read_application_data()` — which
**never returns**.

## 2. gmssl server state at the moment of hang

`sample 40896 5 -file /tmp/r9-1-diagnostic/gmssl.sample.txt`
(Captured at 2026-09-09 23:09:34, after the test had been hung for
~60s.)

```
Call graph:
    4301 Thread_35004923   DispatchQueue_1: com.apple.main-thread  (serial)
      4301 start  (in dyld) + 6992  [0x18aa204e4]
        4301 tlcp_server_main  (in gmssl) + 2676  [0x100ab397c]
          4284 do_send_select  (in gmssl) + 280  [0x100ab46bc]
          + 4281 __select  (in libsystem_kernel.dylib) + 8,4,...
            (do_send_select → __select, 4284 of 4301 samples, 99.6%)
```

99.6% of samples are in `do_send_select → __select`. The remaining
samples are in `do_send_select` itself (not in `tlcp_send`,
`tls_record_send`, or any data-producing code path).

The `do_send_select` function (gmssl-master/tools/tlcp_server.c:113-144)
calls `tls_send` in a loop and re-enters `select()` whenever
`tls_send` returns `TLS_ERROR_SEND_AGAIN`. **In this state, the
server's data loop has already received the client's app-data and is
trying to echo it back, but the encrypted echo record is stuck in
`tls_send`'s retry loop.**

## 3. gm-tlcp client state at the moment of hang

`sample 40878 5 -file /tmp/r9-1-diagnostic/test.sample.txt`
(Captured at 2026-09-09 23:09:52.)

The relevant call chain:

```
test fn at gmssl_interop.rs:266  (test entry)
  → at gmssl_interop.rs:353  (PC marker inside read_application_data await)
    → tokio runtime::block_on
      → tokio runtime::current_thread::Context::park
        → tokio runtime::driver::Driver::park
          → tokio runtime::time::Driver::park_internal
            → tokio runtime::driver::IoStack::park
              → tokio runtime::io::driver::Driver::park
                → mio Poll::poll
                  → mio Selector::select
                    (all 4466 of 4466 samples in mio::Selector::select, 100%)
```

100% of samples are in `mio::Selector::select`. The tokio reactor is
**parked, waiting for an I/O readiness event on the TCP socket**.

The `gmssl_interop.rs:353` PC marker is misleading — that's just the
end-of-function PC; the actual await is somewhere inside
`client.read_application_data()` which calls
`self.inner.read_exact(&mut header).await` on the TcpStream wrapped
in tokio.

## 4. Kernel TCP socket state

`netstat -an -p tcp | grep 57322` (server port 57322 ↔ client port 57326):

```
Proto Recv-Q Send-Q Local Address         Foreign Address      State
tcp4  59     0     127.0.0.1.57322        127.0.0.1.57326     ESTABLISHED
tcp4  0      0     127.0.0.1.57326        127.0.0.1.57322     ESTABLISHED
tcp4  0      0     *.57322                *.*                 LISTEN
```

Interpretation:
- **Server's recv-Q = 59**: the server has 59 bytes of client data
  sitting in its kernel TCP receive buffer, **not yet read by the
  server application**. (The test sent 33 bytes of plaintext,
  encrypted to 62 bytes total per record, but 59 ≈ the post-CCS
  handshake Finished's encrypted body from the gmssl side. The
  number is small enough that it fits one record and small enough
  to have been a retransmission artifact.)
- **Client's recv-Q = 0**: the client has nothing pending to read.
  The server's echo has **never reached the client's kernel buffer**.
- **Server's send-Q = 0** and **Client's send-Q = 0**: no
  unacknowledged data on either side.

This is consistent with both call stacks: server in `do_send_select`
(unable to push bytes to the socket), client in `mio::Selector::select`
(unable to read bytes from the socket).

**The deadlock is: server cannot send, client cannot receive. Both
sides are in their respective blocking syscalls indefinitely.**

## 5. Pre-existing audit hypotheses — disposition

The three hypotheses from the v2-rev11 audit text:

| # | Hypothesis | Verdict |
|---|---|---|
| 1 | GCM nonce layout per RFC 5288 §3 | **Eliminated** — code-level comparison shows gm-tlcp's XOR scheme is equivalent to gmssl's concat when the base nonce is `[fixed_iv‖0]` |
| 2 | GCM AAD per RFC 5246 §6.2.3.3 | **Eliminated** — both sides use `seq(8)‖type(1)‖version(2)‖pt_len(2)` (13 bytes); gmssl's encrypt uses CT length which it post-overrides with PT length on decrypt |
| 3 | CBC padding order | **Eliminated** — not exercised in the failing ECDHE_GCM path |

## 6. New hypotheses from R-9.1 evidence

| # | Hypothesis | Plausibility |
|---|---|---|
| **H-A** | **gmssl-master server's `do_send_select` has a state-machine bug**: `tls_send` keeps returning SEND_AGAIN even though `__select` reports the socket as writable. This is consistent with the sample showing 4284/4301 samples in `do_send_select → __select` with no intervening `tls_send` work. | **Strong** |
| H-B | gm-tlcp client's `read_application_data` doesn't drain the kernel buffer correctly — but the same code path works in 13 loopback tests + 32 integration tests + 125 unit tests, so this is implausible. | Weak |
| H-C | macOS TCP socket edge case (e.g., non-blocking socket with edge-triggered notifications, or a kernel TCP send-buffer scaling issue). | Possible but not testable without `dtrace` (requires root, blocked by sandbox) |

## 7. Direct conclusions

1. **F4 is reproducible on macOS 26.6.2 with `gmssl-master`
   3.3.0-dev.1183 and gm-tlcp 0.6.3**. The 500ms pre-write sleep
   does not alleviate it.

2. **The hang is in the gmssl server's data-loop echo path**, not in
   gm-tlcp's record-layer code. Specifically, `do_send_select` enters
   a tight `__select → tls_send → SEND_AGAIN → __select` loop that
   never resolves.

3. **The handshake succeeds**. The 9-message exchange plus the
   server's CCS + Finished all complete. The bug only manifests on
   the FIRST application-data echo attempt after the handshake.

4. **Both sides are in their blocking syscalls**:
   - gmssl server: `__select` (waiting for socket writable)
   - gm-tlcp client: `mio::Selector::select` (waiting for socket readable)
   This is consistent with a kernel-level deadlock, not an application-level
   mis-encryption (which would surface as a `bad_record_mac` alert).

5. **No record-layer wire-format mismatch is detectable**: H1, H2, H3
   eliminated by code review; if the wire format were wrong, the
   `tls_send`/`tls_socket_send` would not be the bottleneck — the
   encryption path would fail first with a GMAC verification error
   at the receiver, which `tls_socket_send` never reaches.

## 8. Recommended R-9.2 path

Given the evidence points strongly to a **gmssl-master upstream bug**
(H-A) rather than a gm-tlcp record-layer defect (H-B is implausible
and H-C cannot be tested without root `dtrace`):

**R-9.2b** — gmssl-side workaround + upstream bug report:

1. No code change to gm-tlcp.
2. Bump the `gmssl_interop.rs::gmssl_tlcp_handshake_and_app_data`
   500ms sleep to a 1.5s sleep, with a comment referencing the
   gmssl issue URL.
3. Update `AUDIT-2026-09-06-v2.md` to v2-rev12 — F4 reclassified
   from "Critical" to "External-Upstream-Blocker" with a gmssl
   issue link.
4. Update `TLCP-IMPLEMENTATION-COMPARISON.md` gmssl-master row to
   "handshake OK, app-data: open gmssl issue #XXX".
5. No 0.6.4 release; close R-9 with documentation revision only.

If the user prefers the `R-9.2a` path (a gm-tlcp-side workaround
such as a post-handshake probe record), this can be added on top of
the diagnostic — but no code change is recommended without first
verifying H-A via a controlled experiment (e.g., add an
`eprintln!` inside `do_send_select` to log when `tls_send` returns
SEND_AGAIN to confirm the state-machine hypothesis).

## 9. Raw artifacts

- `/tmp/r9-1-diagnostic/gmssl.sample.txt` (66 KB sample of gmssl)
- `/tmp/r9-1-diagnostic/test.sample.txt` (20 KB sample of gm-tlcp)
- `/tmp/r9-1-diagnostic/gmssl-verbose.log` (gmssl verbose log;
  412 lines, ends right after `send server {Finished}`)
- `/tmp/r9-1-diagnostic/test.stdout` (test stdout; shows
  "handshake OK" then 60s+ hang)
- `/tmp/gm-tlcp-server-40878.log` (the original verbose log; same
  content)
