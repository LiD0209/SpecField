# CID peer address update lacks a strict newer-record gate

## Summary
This finding is confirmed as a partial RFC 9146 inconsistency.

wolfSSL implements an important part of the required protection: a pending peer address is promoted only after the next DTLS record has been decrypted and authenticated. However, in the DTLS 1.2 CID pending-peer promotion path, wolfSSL does not also require the triggering record to be newer than the newest datagram already received. The normal DTLS 1.2 replay-window code can accept a valid previous-epoch record, and `dtlsProcessPendingPeer()` promotes `pendingPeer` without an explicit newest-datagram comparison.

Scope: this issue applies when DTLS CID support is built and an application uses `wolfSSL_dtls_set_pending_peer()` for address migration. It is not a claim that wolfSSL automatically accepts source-address changes in the default socket receive path.

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9146#section-6

Section: RFC 9146 Section 6, Peer Address Update

```text
The received datagram is "newer" (in terms of both epoch and sequence number)
than the newest datagram received.
```

RFC 9146 requires a receiver not to replace the peer address for a CID-protected DTLS connection unless the received datagram has been cryptographically verified, is newer than the newest datagram already received, and the implementation has a strategy for ensuring that the new peer address can receive and process DTLS records.

The newer-record condition is separate from ordinary DTLS replay-window acceptance. A datagram can be valid application traffic and still not be eligible to trigger a peer address update.

## Relevant Source Code
`wolfssl-master/src/ssl.c:1459`

```c
int wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
    ...
    else {
        ret = SockAddrSet(&ssl->buffers.dtlsCtx.pendingPeer, peer, peerSz,
                ssl->heap);
    }
    if (ret == WOLFSSL_SUCCESS)
        ssl->buffers.dtlsCtx.processingPendingRecord = 0;
    ...
}
```

`wolfssl-master/src/internal.c:22584`

```c
static void dtlsProcessPendingPeer(WOLFSSL* ssl, int deprotected)
{
    if (ssl->buffers.dtlsCtx.pendingPeer.sa != NULL) {
        if (!deprotected) {
            ...
        }
        else {
            /* Pending peer present and record deprotected. Update the peer. */
            (void)wolfSSL_dtls_set_peer(ssl,
                    ssl->buffers.dtlsCtx.pendingPeer.sa,
                    ssl->buffers.dtlsCtx.pendingPeer.sz);
            ssl->buffers.dtlsCtx.processingPendingRecord = 0;
            dtlsClearPeer(&ssl->buffers.dtlsCtx.pendingPeer);
        }
    }
    ...
}
```

`wolfssl-master/src/internal.c:23283`

```c
if (IsDtlsNotSctpMode(ssl)) {
    DtlsUpdateWindow(ssl);
}
#ifdef WOLFSSL_DTLS_CID
/* Update the peer if we were able to de-protect the message */
if (IsEncryptionOn(ssl, 0))
    dtlsProcessPendingPeer(ssl, 1);
#endif
```

`wolfssl-master/src/internal.c:19034`

```c
if (ssl->keys.curEpoch == peerSeq->nextEpoch) {
    next_hi = peerSeq->nextSeq_hi;
    next_lo = peerSeq->nextSeq_lo;
    window = peerSeq->window;
}
else if (ssl->keys.curEpoch == peerSeq->nextEpoch - 1) {
    next_hi = peerSeq->prevSeq_hi;
    next_lo = peerSeq->prevSeq_lo;
    window = peerSeq->prevWindow;
}
else {
    return 0;
}
```

## Implementation Behavior
`wolfSSL_dtls_set_pending_peer()` stores a candidate peer address in `ssl->buffers.dtlsCtx.pendingPeer`.

During record processing, `dtlsProcessPendingPeer(ssl, 0)` tracks that the next encrypted record is being processed. After a record has been decrypted and authenticated, the DTLS CID path calls `dtlsProcessPendingPeer(ssl, 1)`, which promotes `pendingPeer` with `wolfSSL_dtls_set_peer()`.

The promotion point does not compare the triggering record's epoch and sequence number against a stored "newest datagram received" value. It relies on the normal DTLS record acceptance path. For DTLS 1.2, that path accepts records in the current epoch and also records in the previous epoch window when `ssl->keys.curEpoch == peerSeq->nextEpoch - 1`.

## Inconsistency Reason
RFC 9146 requires all peer-address updates to be gated by a datagram that is both cryptographically verified and newer than the newest datagram already received.

wolfSSL satisfies the cryptographic-verification part for pending-peer promotion, because `pendingPeer` is promoted only after successful record deprotection. The missing part is the strict newer-record gate. A previous-epoch record can be valid under the DTLS replay-window rules, but it is not newer than a later current-epoch datagram. The current promotion code does not distinguish that case before updating the peer address.

This is therefore a partial inconsistency: record authentication is enforced, but RFC 9146's separate newest-datagram requirement is not explicitly enforced on the pending-peer promotion path.

## Static Evidence
Verification script: `test-wolfssl-dtls/rfc9146/001-022/verify_wolfssl_dtls_cid_001_022.py`

Verification log: `test-wolfssl-dtls/rfc9146/001-022/verify_wolfssl_dtls_cid_001_022.log`

Relevant checks from the log:

```text
PASS previous epoch accepted: DTLS 1.2 window logic accepts previous epoch window
PASS pending peer function found: dtlsProcessPendingPeer is present
PASS peer update after deprotect: pending peer is promoted after deprotection
PASS no strict newer gate: peer promotion body has no explicit newest-datagram comparison
```

The same log also includes a default-build probe showing that `WOLFSSL_DTLS_CID` was not enabled in the checked default build. That build-configuration fact is separate from this peer-address update issue.

## Impact
In deployments that enable DTLS CID and use `wolfSSL_dtls_set_pending_peer()` for peer address migration, a valid but not-newer record could promote a pending peer address. This can allow reordered or previous-epoch traffic to drive an address update that RFC 9146 intended to prevent.

The practical impact depends on how the application detects source-address changes and when it calls `wolfSSL_dtls_set_pending_peer()`. The default wolfSSL socket receive path does not, by itself, prove this issue is reachable for every application.

## Fix Direction
Track the epoch and sequence number of the newest datagram received for the connection, independently of the replay-window acceptance decision.

Before promoting `pendingPeer`, compare the triggering record's epoch and sequence number with that newest-datagram state. Only call `wolfSSL_dtls_set_peer()` for address migration when the record is cryptographically verified and strictly newer in the RFC 9146 sense.

The comparison should be placed on the pending-peer promotion path, near `dtlsProcessPendingPeer(ssl, 1)`, so previous-epoch or reordered records can remain valid DTLS records without being allowed to trigger peer address replacement.
