# DTLS 1.2 retransmission does not automatically lower fragment size when PMTU is unknown

## Summary 误报

wolfSSL fragments handshake messages according to the configured MTU and record size, but repeated timeout retransmissions do not appear to trigger automatic smaller fragmentation when the PMTU is unknown.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc6347

RFC 6347 Section 4.2.3, Handshake Message Fragmentation and Reassembly

```text
If a handshake message is too large to fit into a single DTLS record, it MUST be fragmented. Each fragment contains the same message_seq and length, with fragment_offset and fragment_length describing its position. If repeated retransmissions do not result in a response and PMTU is unknown, implementations SHOULD fragment handshake messages.
```

以上英文原文要求实现不仅要有字段编码，还要满足对应的运行时语义。

## Relevant Source Code

```c
src/internal.c:10074
if (ssl->dtls_timeout <  ssl->dtls_timeout_max) {
    ssl->dtls_timeout *= DTLS_TIMEOUT_MULTIPLIER;
    result = 0;
}

src/internal.c:42177
maxFrag -= (recordSz - mtu);

src/ssl.c:1598
int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, word16 newMtu)
```

## Implementation Behavior

SendHandshakeMsg fragments by wolfssl_local_GetMaxPlaintextSize, which is based on the current max fragment/MTU. Timeout handling doubles dtls_timeout and retransmits the saved flight; it does not adjust dtlsMtuSz or fragment size.

## Inconsistency Reason

RFC 6347 recommends fragmenting more aggressively if repeated retransmissions do not receive a response and PMTU is unknown. wolfSSL has MTU-based fragmentation, but not the black-hole detection loop described by that SHOULD.

## Runtime Evidence

The verification script checks the MTU set/get path, fragmentation path, and timeout path, confirming no automatic MTU decrease on repeated timeout.

## Impact

Large handshake flights may continue to be retransmitted at an ineffective size until the application configures a smaller MTU.

## Fix Direction

Track repeated DTLS 1.2 retransmission failures and reduce the handshake fragment size or expose a documented callback/API for PMTU black-hole response.
