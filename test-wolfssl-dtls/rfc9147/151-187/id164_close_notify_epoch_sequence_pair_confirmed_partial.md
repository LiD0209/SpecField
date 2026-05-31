# DTLS 1.3 close_notify Does Not Preserve the Epoch/Sequence Boundary

## Summary

This report verifies ID 164.

RFC 9147 requires a DTLS 1.3 receiver to ignore data whose epoch/sequence number pair is after the pair of a valid received closure alert.

wolfSSL does implement ordinary `close_notify` shutdown handling: it records that `close_notify` was received and returns `ZERO_RETURN` from the alert dispatch path. However, the inspected DTLS 1.3 receive path does not store the `close_notify` record's epoch/sequence number pair and does not compare later records against that saved boundary.

Conclusion: ID 164 is **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 5.10, `Alert Messages`.

Relevant original English text from RFC 9147:

```text
Any data received with an epoch/sequence number pair after that of a
valid received closure alert MUST be ignored.  Note: this is a change
from TLS 1.3 which depends on the order of receipt rather than the
epoch and sequence number.
```

This requirement is DTLS-specific. It is not enough to remember only that the peer sent `close_notify`; the implementation needs the record-number boundary of the valid closure alert.

## Relevant Source Code

### Current DTLS 1.3 Record Number Is Available

`D:\project\wolfssl-master\wolfssl\internal.h`

```c
w64wrapper curEpoch64;    /* Received epoch in current record    */
w64wrapper curSeq;
```

`D:\project\wolfssl-master\src\internal.c`

```c
ssl->keys.curEpoch64 = epochNumber;

ret = Dtls13ReconstructSeqNumber(ssl, &hdrInfo, &ssl->keys.curSeq);
```

This shows that wolfSSL reconstructs the current received DTLS 1.3 epoch and sequence number.

### close_notify Is Stored as a Boolean

`D:\project\wolfssl-master\wolfssl\internal.h`

```c
word16            closeNotify:1;      /* we've received a close notify */
```

No adjacent `closeNotifyEpoch`, `closeNotifySeq`, `close_notify_epoch`, `close_notify_seq`, `closureEpoch`, or `closureSeq` field was found in the audited headers.

### DoAlert Marks close_notify as Received

`D:\project\wolfssl-master\src\internal.c`

```c
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}
```

This satisfies the basic shutdown-state part of close_notify processing.

### The Alert Dispatch Returns ZERO_RETURN

`D:\project\wolfssl-master\src\internal.c`

```c
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx =
        ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```

This is normal API-level shutdown behavior, but it does not implement the RFC 9147 rule that later data be ignored based on the closure alert's epoch/sequence pair.

## Runtime Evidence

A focused compiled C harness was added:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\151-187\repro_close_notify_164_epoch_sequence_source_check.c
```

The harness was compiled with Clang and executed. Its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\151-187\repro_close_notify_164_epoch_sequence_source_check.log
```

Observed output:

```text
PASS present: DTLS 1.3 current record epoch is reconstructed
PASS present: DTLS 1.3 current record sequence is reconstructed
PASS present: current DTLS 1.3 record epoch field exists
PASS present: current DTLS 1.3 record sequence field exists
PASS present: close_notify boolean state exists
PASS present: DoAlert marks close_notify as received
PASS present: close_notify dispatch returns ZERO_RETURN
PASS absent: stored closeNotifyEpoch boundary field
PASS absent: stored closeNotifySeq boundary field
PASS absent: stored close_notify_epoch boundary field
PASS absent: stored close_notify_seq boundary field
PASS absent: stored closureEpoch boundary field
PASS absent: stored closureSeq boundary field
RESULT confirmed partial: close_notify shutdown is implemented, but no stored epoch/sequence boundary for RFC 9147 post-close ignore logic was found.
```

This is a compiled source-behavior verification. It confirms both the implemented close_notify path and the absence of the structural state needed to enforce the RFC 9147 epoch/sequence boundary.

## Inconsistency Reason

| Requirement component | wolfSSL behavior | Result |
|---|---|---|
| Process a valid `close_notify` alert | `DoAlert` sets `ssl->options.closeNotify`; alert dispatch returns `ZERO_RETURN` | Satisfied |
| Preserve the valid closure alert's epoch/sequence pair | Current record pair exists as `curEpoch64`/`curSeq`, but no closure-boundary pair is stored | Missing |
| Ignore later data by comparing epoch/sequence pair | No close_notify boundary comparison was found in the audited receive implementation | Missing |

The mismatch is partial. wolfSSL implements close_notify as a shutdown signal, but the inspected DTLS 1.3 code does not implement the record-number boundary rule required by RFC 9147 Section 5.10.

## Impact

This affects DTLS 1.3 behavior after a valid closure alert. If records are reordered around shutdown, the RFC requires the receiver to decide whether later data must be ignored by comparing epoch/sequence number pairs. Without storing the closure alert pair, the implementation relies on generic shutdown behavior rather than the normative DTLS record-ordering rule.

## Fix Direction

Store the epoch and sequence number of a valid received `close_notify` alert in DTLS 1.3 connection state. Then, before dispatching later DTLS 1.3 records, compare the reconstructed record pair against that stored closure boundary and ignore data whose pair is after it. Add tests that inject data records before and after a valid `close_notify` pair to verify the ordering rule.
