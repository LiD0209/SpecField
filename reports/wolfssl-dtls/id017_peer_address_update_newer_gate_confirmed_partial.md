# CID peer address update lacks a strict newer sequence-number gate

## Summary

Verification result: `confirmed_partial`.

RFC 9146 Section 6 requires a DTLS CID receiver to replace its peer address only when all peer-address-update conditions are met. One of those conditions is that the datagram triggering the address update is "newer" than the newest datagram already received, considering both epoch and sequence number.

wolfSSL implements an important part of this requirement: a pending peer address is promoted only after the next encrypted DTLS record has been successfully deprotected. However, the promotion path does not also check whether the triggering record is newer than the newest datagram already received. A focused runtime test confirms that a valid but not-newer DTLS 1.2 CID record can still promote `pendingPeer` to the active peer address.

Scope: this finding applies when DTLS CID support is enabled and an application uses `wolfSSL_dtls_set_pending_peer()` for address migration. It is not a claim that wolfSSL's default socket receive path unconditionally accepts arbitrary source-address changes.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9146#section-6

Section: RFC 9146 Section 6, Peer Address Update

```text
When a record with a CID is received that has a source address
different from the one currently associated with the DTLS connection,
the receiver MUST NOT replace the address it uses for sending records
to its peer with the source address specified in the received
datagram, unless the following three conditions are met:

*  The received datagram has been cryptographically verified using
   the DTLS record layer processing procedures.

*  The received datagram is "newer" (in terms of both epoch and
   sequence number) than the newest datagram received.
```

The "newer" condition is separate from ordinary DTLS replay-window acceptance. A datagram can be a valid DTLS record and still be ineligible to trigger a peer address update.

## Relevant Source Code

`wolfssl-master/src/ssl.c:1480`

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

`wolfSSL_dtls_set_pending_peer()` stores a candidate address in `ssl->buffers.dtlsCtx.pendingPeer`; it does not store the current record epoch/sequence number or compare it with a newest-datagram state.

`wolfssl-master/src/internal.c:22899`

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

After deprotection, the pending peer is promoted directly with `wolfSSL_dtls_set_peer()`.

`wolfssl-master/src/internal.c:23607`

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

This confirms that wolfSSL has a cryptographic/deprotection gate before pending-peer promotion.

`wolfssl-master/src/internal.c:19333`

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

The DTLS 1.2 replay-window path can accept records from the current epoch, and also previous-epoch records when they fall within the allowed window.

## Implementation Behavior

The implementation flow is:

1. The application calls `wolfSSL_dtls_set_pending_peer()` after observing a candidate source-address change.
2. wolfSSL stores that candidate in `pendingPeer`.
3. During record processing, `dtlsProcessPendingPeer(ssl, 0)` marks that a pending peer is tied to the next encrypted record.
4. After successful deprotection, `dtlsProcessPendingPeer(ssl, 1)` promotes `pendingPeer` by calling `wolfSSL_dtls_set_peer()`.

What is missing is an address-update-specific comparison between the triggering record's epoch/sequence number and the newest datagram already received. wolfSSL relies on the normal DTLS record acceptance path, but replay-window acceptance is weaker than RFC 9146's "newer than newest" update condition.

## Inconsistency Reason

RFC 9146 requires peer-address replacement to be gated by a datagram that is both cryptographically verified and newer than the newest datagram already received.

wolfSSL satisfies the cryptographic-verification part for the pending-peer path: `pendingPeer` is promoted only after the record is successfully deprotected. The missing part is the strict newer-datagram gate. A reordered but valid record, with a sequence number older than a record already received, can still pass DTLS replay-window checks and be delivered to the application. Under RFC 9146, that record must not trigger peer-address replacement.

Therefore this is a partial inconsistency: CID parsing and deprotection gating exist, but pending-peer promotion does not enforce the separate RFC 9146 newer-than-newest condition.

## Runtime Evidence

Focused test added:

- `wolfssl-master/tests/api/test_dtls.c:525`
- `wolfssl-master/tests/api/test_dtls.h:28`
- `wolfssl-master/tests/api/test_dtls.h:88`

The test `test_wolfSSL_dtls_cid_pending_peer_not_newer()` creates this sequence:

1. Establish a DTLS 1.2 connection with CID enabled.
2. Generate two valid client-to-server application records: `old0` first, then `new1`.
3. Deliver `new1` to the server first; the server successfully reads it.
4. Set `pendingPeer` to `"peer2"`.
5. Deliver the older `old0` record; the server successfully reads it.
6. Assert that `wolfSSL_dtls_get_peer()` still reports no promoted peer, because `old0` is not newer than `new1`.

Build command:

```powershell
cmake -S .\wolfssl-master `
  -B .\test-wolfssl-dtls\rfc9146\001-022\runtime-id017-build `
  -G Ninja `
  -DCMAKE_BUILD_TYPE=Debug `
  -DCMAKE_C_COMPILER=gcc `
  -DWOLFSSL_DTLS=yes `
  -DWOLFSSL_TLS13=yes `
  -DWOLFSSL_DTLS13=yes `
  -DWOLFSSL_DTLS_CID=yes `
  -DWOLFSSL_EXAMPLES=yes `
  -DWOLFSSL_CRYPT_TESTS=no

cmake --build .\test-wolfssl-dtls\rfc9146\001-022\runtime-id017-build --target unit_test -j 4
```

Runtime command:

```powershell
$build = (Resolve-Path ..\test-wolfssl-dtls\rfc9146\001-022\runtime-id017-build).Path
$env:PATH = $build + ';' + $env:PATH
& "$build\tests\unit.test.exe" --api -test_wolfSSL_dtls_cid_pending_peer_not_newer
```

Observed result:

```text
starting unit tests...
 Begin API Tests
  Begin Group: dtls
   1409: test_wolfSSL_dtls_cid_pending_peer_not_newer       :
ERROR - D:/project/SpecTrace/wolfssl-master/tests/api/test_dtls.c line 579 failed with:
    expected: wolfSSL_dtls_get_peer(ssl_s, peer, &peerSz) == 0
    result:   1 != 0

FAILURES:
   1409: test_wolfSSL_dtls_cid_pending_peer_not_newer

 End API Tests
 Failed/Skipped/Passed/All: 1/0/0/1
```

The failure means `wolfSSL_dtls_get_peer()` returned success after the older `old0` record was processed. In other words, the older but valid record promoted `pendingPeer` to the active peer address, which RFC 9146's newer-than-newest gate should prevent.

Control test:

```powershell
& "$build\tests\unit.test.exe" --api -test_wolfSSL_dtls_set_pending_peer
```

Observed result:

```text
test_wolfSSL_dtls_set_pending_peer : passed
Failed/Skipped/Passed/All: 0/0/1/1
```

The existing positive pending-peer test passes in the same build, so the failing focused test is not caused by a broken test harness or failed CID setup.

## Impact

In deployments that enable DTLS CID and use `wolfSSL_dtls_set_pending_peer()` for address migration, a valid but not-newer record can update the active peer address. This can let reordered traffic trigger an address change that RFC 9146 intended to prevent.

The practical reachability depends on how the application detects source-address changes and when it calls `wolfSSL_dtls_set_pending_peer()`, but the runtime test demonstrates that the library's pending-peer promotion path itself does not enforce the RFC 9146 newer-than-newest requirement.

## Fix Direction

Track the newest received datagram for the CID-protected DTLS connection, including at least epoch and sequence number.

Before promoting `pendingPeer` in `dtlsProcessPendingPeer(ssl, 1)`, compare the triggering record's epoch/sequence number with that newest-datagram state. Only call `wolfSSL_dtls_set_peer()` when the record has been cryptographically verified and is strictly newer in the RFC 9146 sense.

The normal replay-window logic should continue to decide whether a record is acceptable DTLS traffic. The new gate should only decide whether that accepted record is eligible to trigger peer-address replacement.
