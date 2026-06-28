# DTLS 1.3 close_notify Lacks Epoch/Sequence Boundary Tracking

## Summary

This report verifies ID 164.

RFC 9147 Section 5.10 requires a DTLS 1.3 receiver to ignore data whose `epoch/sequence number` pair is after the pair of a valid received closure alert. This is a DTLS-specific ordering rule: because DTLS records can arrive out of order, the receiver must reason from the record number pair, not only from the order in which records happen to be received.

wolfSSL implements ordinary `close_notify` handling. When a valid `close_notify` is processed, it records that the peer sent a close notification, skips the remaining input buffer, and returns `ZERO_RETURN` to the application. That prevents normal delivery of later data after the connection has entered the close-notify path.

The missing part is the RFC 9147 boundary semantics. The inspected DTLS 1.3 receive path reconstructs the current record's epoch and sequence number, but it does not store the `close_notify` record's epoch/sequence pair and does not compare later records against that saved closure boundary.

Conclusion: ID 164 is **confirmed partial**. The basic shutdown behavior is implemented, but the DTLS 1.3 epoch/sequence closure-boundary rule is not implemented as specified.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Local standard text: `document/dtls/RFC9147.txt`

Relevant section: RFC 9147 Section 5.10, `Alert Messages`.

Relevant normative text:

```text
Any data received with an epoch/sequence number pair after that of a
valid received closure alert MUST be ignored.  Note: this is a change
from TLS 1.3 which depends on the order of receipt rather than the
epoch and sequence number.
```

This requirement does not merely say "stop reading when a close alert is received". It says the ignore decision is tied to the `epoch/sequence number pair` of the valid closure alert.

## Relevant Source Code

### Current DTLS 1.3 Record Number Is Available

`wolfssl-master/wolfssl/internal.h:2929`

```c
w64wrapper curEpoch64;    /* Received epoch in current record    */
w64wrapper curSeq;
```

`wolfssl-master/src/internal.c:12230`

```c
ssl->keys.curEpoch64 = epochNumber;

ret = Dtls13ReconstructSeqNumber(ssl, &hdrInfo, &ssl->keys.curSeq);
```

wolfSSL reconstructs the DTLS 1.3 epoch and sequence number for the current received record. Therefore the information needed to identify the `close_notify` record boundary exists at record-processing time.

### close_notify Is Stored as a Boolean

`wolfssl-master/wolfssl/internal.h:5136`

```c
word16            closeNotify:1;      /* we've received a close notify */
```

The receive state records only that `close_notify` was received. Repository-wide checks did not find a corresponding stored closure boundary such as `closeNotifyEpoch`, `closeNotifySeq`, `close_notify_epoch`, `close_notify_seq`, `closureEpoch`, or `closureSeq`.

### DoAlert Marks close_notify as Received

`wolfssl-master/src/internal.c:22545`

```c
ssl->options.closeNotify = 1;
```

This satisfies the basic close-notify state update: wolfSSL recognizes the alert and records the shutdown condition.

### Alert Dispatch Stops Normal Processing

`wolfssl-master/src/internal.c:23991`

```c
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx =
        ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```

When `close_notify` is seen, wolfSSL skips the rest of the currently buffered input and returns `ZERO_RETURN`.

`wolfssl-master/src/internal.c:27069`

```c
WOLFSSL_MSG("Zero return, no more data coming");
return 0; /* no more data coming */
```

`wolfssl-master/src/internal.c:27027`

```c
WOLFSSL_MSG("User calling wolfSSL_read in error state, not allowed");
return error;
```

After `ZERO_RETURN`, later reads are not treated as ordinary application-data reads. This is valid ordinary shutdown behavior, but it is not the same as saving a DTLS `epoch/sequence` boundary and comparing future records against it.

## Implementation Behavior

Implemented behavior:

| Requirement component | wolfSSL behavior | Result |
|---|---|---|
| Recognize `close_notify` | `DoAlert` sets `ssl->options.closeNotify` | Satisfied |
| Signal clean shutdown to the application | Alert dispatch returns `ZERO_RETURN` | Satisfied |
| Avoid normal delivery after close-notify path | Input buffer is skipped and subsequent read state returns no more data / error state | Largely satisfied as generic shutdown |

Missing behavior:

| RFC 9147 Section 5.10 requirement | wolfSSL audited behavior | Result |
|---|---|---|
| Preserve the valid closure alert's `epoch/sequence` pair | Current record pair exists as `curEpoch64`/`curSeq`, but no close-notify boundary pair is stored | Missing |
| Ignore data by comparing its pair to the closure boundary | No close-notify boundary comparison was found in the DTLS 1.3 receive path | Missing |

## Inconsistency Reason

The inconsistency is partial, not total.

wolfSSL implements `close_notify` as a shutdown event. Once the alert is processed, it enters a `ZERO_RETURN` path and does not continue normal application-data delivery.

RFC 9147 requires a more precise DTLS 1.3 rule: the receiver must ignore data whose `epoch/sequence number` pair is after the pair of the valid closure alert. This matters because DTLS records may be reordered. A receiver may encounter records in a different order from their record-number order, so the closure boundary is defined by the record pair, not merely by the moment the alert is processed.

In short:

```text
RFC 9147: ignore post-closure data according to the close_notify epoch/sequence boundary.
wolfSSL: treats close_notify as a generic shutdown signal and does not store/compare that boundary.
```

## Static Evidence

Source-behavior harness:

`test-wolfssl-dtls/rfc9147/151-187/repro_close_notify_164_epoch_sequence_source_check.c`

Observed log:

`test-wolfssl-dtls/rfc9147/151-187/repro_close_notify_164_epoch_sequence_source_check.log`

Selected results:

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

This harness is a compiled source-behavior check. It confirms the implemented close-notify path and the absence of obvious structural state for the RFC 9147 boundary. It is not a packet-level reorder test, so the strongest supported conclusion is **confirmed partial** rather than a fully demonstrated runtime misdelivery.

## Impact

The practical risk is around DTLS record reordering near shutdown.

For example, if a valid `close_notify` has pair `(epoch=3, seq=10)`, RFC 9147 requires data with a later pair such as `(epoch=3, seq=11)` to be ignored. The implementation should make this decision by comparing record pairs. wolfSSL instead relies on the generic close-notify shutdown path, so the protocol-specific boundary is not represented in connection state.

This may affect strict DTLS 1.3 conformance and interoperability with peers or tests that verify closure behavior by record-number ordering.

## Fix Direction

1. Add DTLS 1.3 receive-side state to store the epoch and sequence number of a valid received `close_notify`.
2. Set that state when `DoAlert` processes a valid `close_notify`, using the current `ssl->keys.curEpoch64` and `ssl->keys.curSeq`.
3. Before dispatching later DTLS 1.3 records, compare the reconstructed record pair against the saved closure boundary.
4. Ignore data records whose pair is after the saved closure boundary.
5. Add packet-level tests that inject records before and after a valid `close_notify` pair, including reordered delivery cases.
