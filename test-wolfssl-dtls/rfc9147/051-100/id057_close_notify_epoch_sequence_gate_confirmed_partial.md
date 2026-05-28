# DTLS 1.3 close_notify does not preserve the closure record-number boundary

## Summary
wolfSSL records that a close_notify alert was received, but the audited DTLS 1.3 path does not preserve the alert's epoch/sequence number pair and does not compare later records against that boundary.

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section 5.8, Closure Alerts:

```text
Any data received with an epoch/sequence number pair after that of a valid received closure alert MUST be ignored.
```

该要求不是简单的 API shutdown 状态，而是要求 DTLS 接收端按 record number 顺序忽略 closure alert 之后的数据。

## Relevant Source Code
`src/internal.c:22226`

```c
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}
```

`src/internal.c:23663`

```c
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx =
        ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```

## Implementation Behavior
The implementation handles close_notify as a shutdown signal and returns ZERO_RETURN for the current read. The WOLFSSL object keeps current DTLS record fields such as curEpoch64/curSeq, but no closeNotifyEpoch/closeNotifySeq-style boundary is stored.

## Inconsistency Reason
The standard requires an ordering boundary based on the valid closure alert's epoch/sequence pair. wolfSSL implements close_notify state but does not retain or enforce that pair for future datagrams, so later DTLS records are not filtered by the required boundary in the audited code path.

## Runtime Evidence
`verify_wolfssl_dtls13_051_100.py::test_close_notify_lacks_epoch_sequence_gate` passed. The test confirms close_notify state exists and no stored closure pair or post-close pair comparison is present.

## Impact
A peer that sends data after a valid close_notify should have that later data ignored according to RFC 9147. Without a record-number boundary, behavior depends on higher-level shutdown handling rather than the required DTLS ordering rule.

## Fix Direction
Store the epoch and sequence number of the valid received closure alert. In DTLS 1.3 record receive processing, ignore records whose reconstructed epoch/sequence pair is later than the stored closure boundary.
