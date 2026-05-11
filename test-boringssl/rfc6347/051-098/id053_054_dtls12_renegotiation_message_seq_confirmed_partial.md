# DTLS 1.2 Renegotiation Message Sequence Is Unsupported

## Summary

BoringSSL implements DTLS handshake sequence numbers for initial handshakes, but DTLS 1.2 renegotiation is explicitly unsupported, so the rehandshake-specific HelloRequest and ServerHello message_seq examples are only partially satisfied.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc6347>

Section: RFC 6347 Section 4.2.2, Handshake Message Format

Original English excerpt:

```text
The first message each side transmits in each handshake always has message_seq = 0.
```

The relevant requirement is that a DTLS implementation support the stated DTLS 1.2 behavior under the condition captured by the extracted rule.

## Relevant Source Code

```c++
ssl/d1_both.cc:550
bool dtls1_init_message(const SSL *ssl, CBB *cbb, CBB *body, uint8_t type) {
  if (!CBB_init(cbb, 64) ||
      !CBB_add_u8(cbb, type) ||
      !CBB_add_u24(cbb, 0) ||
      !CBB_add_u16(cbb, ssl->d1->handshake_write_seq) ||
      !CBB_add_u24(cbb, 0) ||
      !CBB_add_u24_length_prefixed(cbb, body)) {
    return false;
  }
  return true;
}

ssl/d1_pkt.cc:184
// DTLS resets handshake message numbers on each handshake, so renegotiations
// and retransmissions are ambiguous.
...
// Otherwise, this is a pre-CCS handshake message from an unsupported
// renegotiation attempt. Fall through to the error path.
```

## Implementation Behavior

The initial-handshake sequence machinery is present: outgoing DTLS handshake messages carry handshake_write_seq and increment after each new message. Incoming messages are matched against handshake_read_seq. After the handshake, however, DTLS 1.2 handshake records are treated as unsupported renegotiation rather than a new supported handshake.

## Inconsistency Reason

The standard describes message_seq behavior for every handshake, including rehandshake examples. BoringSSL implements the generic counter but deliberately does not implement DTLS renegotiation, so the exact rehandshake condition cannot be exercised. This is partial compliance for the extracted item: implemented for supported handshakes, absent for unsupported rehandshake.

## Runtime Evidence

The focused probe `repro_dtls12_hvr_static_probe.exe` was compiled and run successfully. See `repro_dtls12_hvr_static_probe.log`.

## Impact

Applications depending on DTLS 1.2 renegotiation will not get RFC-style rehandshake sequencing from BoringSSL. Modern deployments commonly avoid renegotiation, so the practical risk is low but the extracted requirement is not fully implemented.

## Fix Direction

If DTLS 1.2 renegotiation were ever reintroduced, reset/read/write message_seq handling would need explicit test coverage for HelloRequest and the first server response. If renegotiation remains unsupported, document the intentional non-support near the DTLS method/API surface.
