# 0-RTT Data Security Considerations

## Overview

0-RTT (Zero Round Trip Time) data is early application data sent by a client before the TLS handshake completes. This can reduce latency for resumed connections but introduces significant security risks.

## Security Risks

### 1. Replay Attacks

**Severity: High**

0-RTT data is encrypted using a pre-shared key (PSK) from a previous session. An attacker can:
1. Intercept a legitimate 0-RTT message
2. Replay it to the server multiple times
3. Cause the server to process the same request multiple times

**Impact Examples:**
- Duplicate financial transactions
- Repeated database operations
- Multiple authentication attempts

### 2. Forward Secrecy Not Guaranteed

**Severity: Medium**

0-RTT data is encrypted with a key derived from a long-term PSK. If the PSK is compromised (e.g., through a server breach), previously captured 0-RTT data can be decrypted.

### 3. No Server Authentication

**Severity: High**

When a client sends 0-RTT data, the server has not yet proven its identity to the client. A man-in-the-middle could potentially:
1. Intercept the connection
2. Respond with its own certificate
3. Receive and decrypt 0-RTT data intended for the legitimate server

## Implementation Requirements (RFC 8446)

If 0-RTT support is added in the future, the following MUST be implemented:

### Anti-Replay Mechanism

```
┌─────────────────────────────────────────────────────────────┐
│                    Anti-Replay Protection                     │
├─────────────────────────────────────────────────────────────┤
│ 1. Single Use Tickets: Session tickets MUST be invalidated  │
│    after use (one-shot PSKs)                                │
│                                                              │
│ 2. Client Hello Recording: Store hash of ClientHello with  │
│    each ticket, reject duplicates                           │
│                                                              │
│ 3. Rate Limiting: Limit 0-RTT attempts per connection      │
│                                                              │
│ 4. Application-Layer Replay Detection: Application should │
│    implement idempotency checks for 0-RTT requests          │
└─────────────────────────────────────────────────────────────┘
```

### Required Behaviors

1. **Server MUST** reject 0-RTT data if the session ticket was already used
2. **Server MUST** validate that 0-RTT data doesn't violate application invariants
3. **Client SHOULD** only send 0-RTT data for idempotent requests
4. **Applications MUST** treat 0-RTT data as potentially replayed

## Current Status

**gm-tls does NOT support 0-RTT data.**

Reasons:
1. Session resumption infrastructure exists but is not fully integrated
2. No PSK (Pre-Shared Key) mode is implemented
3. Anti-replay mechanisms are not in place

## Future Implementation Path

To safely implement 0-RTT, the following must be completed:

1. **Session Resumption Integration** (Prerequisite)
   - Complete the session ticket handshake integration
   - Implement server-side session ticket state management

2. **PSK Mode**
   - Implement PSK cipher suites
   - Add PSK to key derivation

3. **Anti-Replay Infrastructure**
   - Single-use ticket mechanism
   - ClientHello hash storage and checking
   - Rate limiting

4. **Application Guidance**
   - Document safe 0-RTT usage patterns
   - Provide idempotency guidelines

## Recommendations

### For Applications Using gm-tls

1. **DO NOT** request 0-RTT for non-idempotent operations
2. **DO** implement application-level idempotency tokens
3. **DO** monitor for suspicious duplicate requests
4. **DO** use session resumption with full handshake for sensitive operations

### For 0-RTT Implementation Projects

If you need to add 0-RTT support:

1. Start with comprehensive threat modeling
2. Implement anti-replay BEFORE enabling 0-RTT
3. Consider 0-RTT as a performance optimization, not a security feature
4. Provide clear application-level documentation

## References

- [RFC 8446 - TLS 1.3](https://tools.ietf.org/html/rfc8446#section-2.3)
- [RFC 8446 - Section 8: 0-RTT](https://tools.ietf.org/html/rfc8446#section-8)
- [IETF TLS Working Group - 0-RTT Analysis](https://tools.ietf.org/html/draft-ietf-tls-0rtt-analysis)
