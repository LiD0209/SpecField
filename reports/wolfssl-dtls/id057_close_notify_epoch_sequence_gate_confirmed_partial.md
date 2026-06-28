# DTLS 1.3 close_notify Does Not Preserve the Epoch/Sequence Boundary

## Summary

RFC 9147 requires a DTLS 1.3 receiver to ignore data whose epoch/sequence number pair is after the pair of a valid received closure alert.

wolfSSL implements `close_notify` as a shutdown signal: it records that `close_notify` was received and returns `ZERO_RETURN` from the read path. However, the audited DTLS 1.3 receive path does not store the closure alert's epoch/sequence pair, and a focused runtime test shows that wolfSSL closes by receive order rather than preserving the RFC 9147 record-number boundary.

This finding is therefore **partially satisfied**: basic `close_notify` shutdown handling exists, but the DTLS 1.3 epoch/sequence boundary rule is not implemented.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Section 5.10, `Alert Messages`, states:

```text
Any data received with an epoch/sequence number pair after that of a
valid received closure alert MUST be ignored.
```

The same paragraph explains that DTLS 1.3 differs from TLS 1.3 here:

```text
Note: this is a change from TLS 1.3 which depends on the order of receipt
rather than the epoch and sequence number.
```

This is not only an API-level shutdown requirement. Because DTLS records can be reordered, the receiver needs the valid `close_notify` record's `(epoch, sequence_number)` boundary. Data with a pair after that boundary must be ignored; data with a pair before that boundary should not be rejected merely because it arrived after the alert.

## Relevant Source Code

### Current Record Epoch and Sequence Are Tracked

In `wolfssl-master/wolfssl/internal.h`, wolfSSL stores the current received DTLS record number:

```c
/* wolfssl-master/wolfssl/internal.h:2924 */
word16 curEpoch;    /* Received epoch in current record    */
word16 curSeq_hi;   /* Received sequence in current record */
word32 curSeq_lo;

#ifdef WOLFSSL_DTLS13
w64wrapper curEpoch64;    /* Received epoch in current record    */
w64wrapper curSeq;
#endif /* WOLFSSL_DTLS13 */
```

The DTLS 1.3 unified header parser fills these fields:

```c
/* wolfssl-master/src/internal.c:12230 */
ssl->keys.curEpoch64 = epochNumber;

ret = Dtls13ReconstructSeqNumber(ssl, &hdrInfo, &ssl->keys.curSeq);
```

So the record parser has access to the current record's epoch and sequence number.

### close_notify Is Stored as a Boolean

In `wolfssl-master/wolfssl/internal.h`, the connection options contain a single close-notify bit:

```c
/* wolfssl-master/wolfssl/internal.h:5136 */
word16            closeNotify:1;      /* we've received a close notify */
```

No adjacent field stores the epoch/sequence pair of the received closure alert.

### DoAlert Marks close_notify as Received

In `wolfssl-master/src/internal.c`, `DoAlert` parses the alert and records `close_notify`:

```c
/* wolfssl-master/src/internal.c:22544 */
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}
```

This satisfies the basic shutdown-state part of the behavior.

### Alert Dispatch Returns ZERO_RETURN

The alert dispatch path treats `close_notify` as a clean shutdown signal:

```c
/* wolfssl-master/src/internal.c:23991 */
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx =
        ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```

After this, later `wolfSSL_read()` calls see the existing error state and do not continue processing queued records:

```c
/* wolfssl-master/src/internal.c:27019 */
if (error != 0 && error != WC_NO_ERR_TRACE(WANT_WRITE)
    ...
) {
    WOLFSSL_MSG("User calling wolfSSL_read in error state, not allowed");
    return error;
}
```

This is shutdown-by-receipt behavior. It does not preserve the DTLS 1.3 closure alert's epoch/sequence boundary.

## Implementation Behavior

The observed receive behavior is:

```text
received close_notify
    -> closeNotify = 1
    -> return ZERO_RETURN
    -> later reads remain in zero-return/closed state
```

The RFC 9147 behavior requires:

```text
received valid close_notify at (epoch, sequence)
    -> store closure boundary
    -> ignore data whose (epoch, sequence) is after that boundary
    -> do not turn this into a pure receive-order cutoff
```

The implementation has replay/window checks for DTLS records, but those checks are based on the current decrypt epoch and replay window. They are not a stored `close_notify` boundary comparison.

## Runtime Evidence

A focused runtime test was added:

```text
test-wolfssl-dtls/rfc9147/051-100/id057_close_notify_epoch_sequence_runtime.c
```

The test builds wolfSSL with DTLS 1.3 enabled under:

```text
test-wolfssl-dtls/rfc9147/051-100/cmake-id057-runtime/
```

The harness creates a DTLS 1.3 client/server pair with controlled in-memory datagram queues. It first verifies normal application-data delivery, then generates these client-to-server records:

```text
OLD application data
NEW application data
close_notify
```

It then deliberately delivers them to the server in this order:

```text
close_notify
OLD application data
```

Under the RFC 9147 epoch/sequence rule, `OLD` was generated before `close_notify`, so it should not be rejected merely because it arrived after the alert.

Observed output:

```text
handshake ok
write baseline ret=4 queued_to_server=1
read baseline ret=4 err=0 data=BASE
write old ret=3 queued_to_server=1
write new ret=3 queued_to_server=1
shutdown ret=2 queued_to_server=1
read close_notify first ret=0 err=6
read old data after close_notify ret=-1 err=6
RESULT nonconformant-or-closed: lower-sequence data was not delivered after close_notify arrived first
```

The saved log is:

```text
test-wolfssl-dtls/rfc9147/051-100/id057_close_notify_epoch_sequence_runtime.log
```

The baseline line proves that the harness can deliver DTLS 1.3 application data normally:

```text
read baseline ret=4 err=0 data=BASE
```

The reordered close test then shows that once `close_notify` is received, later reads remain in zero-return/closed state and the lower-sequence `OLD` data is not delivered:

```text
read close_notify first ret=0 err=6
read old data after close_notify ret=-1 err=6
```

## Inconsistency Reason

| Requirement component | wolfSSL behavior | Result |
|---|---|---|
| Treat `close_notify` as connection closure | `DoAlert` sets `ssl->options.closeNotify`; alert dispatch returns `ZERO_RETURN` | Satisfied |
| Preserve the valid closure alert's epoch/sequence pair | Current record pair exists as `curEpoch64`/`curSeq`, but no closure-boundary pair is stored | Missing |
| Ignore later data by comparing epoch/sequence pair | Runtime behavior follows receive-order shutdown; lower-sequence application data delivered after the alert is not processed | Missing |

The mismatch is therefore partial. wolfSSL implements `close_notify` shutdown state, but it does not implement the RFC 9147 DTLS 1.3 record-number boundary rule.

## Impact

This affects reordered DTLS 1.3 traffic around connection closure. If a valid `close_notify` datagram arrives before earlier application-data datagrams, wolfSSL reports clean shutdown and does not deliver the earlier data. RFC 9147 requires the closure decision for later data to be based on the alert's epoch/sequence pair, not purely on receive order.

## Fix Direction

Store the epoch and sequence number of the valid received `close_notify` alert in DTLS 1.3 connection state. Then, in the DTLS 1.3 receive path, compare each later record's reconstructed `(epoch, sequence)` against the stored closure boundary and ignore only records after that boundary.
