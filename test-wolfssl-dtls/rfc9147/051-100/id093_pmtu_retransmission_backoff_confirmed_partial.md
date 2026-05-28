# DTLS 1.3 retransmission path lacks PMTU-unknown record-size backoff evidence

## Summary
wolfSSL supports DTLS 1.3 handshake fragmentation and retransmission, but the audited retransmission timeout path does not show a strategy to back off to smaller record sizes after repeated retransmissions when PMTU is unknown.

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section 4.4, Handshake Message Fragmentation and Reassembly:

```text
If repeated retransmissions do not result in a response, and the PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size, fragmenting the handshake message as appropriate.
```

该 SHOULD 约束针对重复重传失败后的自适应行为，不等同于初次发送时支持分片。

## Relevant Source Code
`src/dtls13.c:2089`

```c
maxFrag = wolfssl_local_GetMaxPlaintextSize(ssl);
maxLen = length;

if (maxLen < maxFrag) {
    ret = Dtls13SendOneFragmentRtx(...);
}
else {
    ret = Dtls13SendFragmented(...);
}
```

`src/dtls13.c:2810`

```c
/* Send ACKs when available after a timeout but only retransmit the last
 * flight after a long timeout */
int Dtls13RtxTimeout(WOLFSSL* ssl)
```


## Implementation Behavior
Initial send uses current max plaintext/MTU sizing and can fragment. Timeout handling resends buffered messages through Dtls13RtxSendBuffered(), but the reviewed path does not adjust PMTU, shrink max fragment size, or re-fragment to smaller records as retransmissions repeat.

## Inconsistency Reason
The implementation covers basic fragmentation and retransmission. The missing part is the adaptive backoff condition: repeated no-response retransmissions with unknown PMTU should lead to smaller records.

## Runtime Evidence
`verify_wolfssl_dtls13_051_100.py::test_retransmission_pmtu_backoff_not_present` passed. The test confirms fragmentation and retransmission functions exist, but the retransmission timeout body lacks PMTU/backoff/size-shrink logic.

## Impact
On paths where PMTU discovery is unavailable and large handshake records are black-holed, retransmissions may keep using the same size instead of converging to smaller fragments.

## Fix Direction
Track repeated retransmission failures when PMTU is unknown, reduce the record-size target, and re-fragment queued handshake messages before subsequent retransmissions.
