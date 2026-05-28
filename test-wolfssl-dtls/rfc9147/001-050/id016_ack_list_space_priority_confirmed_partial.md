# DTLS 1.3 ACK Space-Limited Priority Is Incomplete

## Summary

wolfSSL implements DTLS 1.3 ACK record-number collection, sorting, duplicate suppression, ACK serialization, and ACK processing. The gap is narrower: when the ACK list is full, the implementation silently drops the newly observed record instead of preferring records that have not yet been acknowledged.

## Standard Requirement

Standard: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: `7.1 ACK Message`

Relevant original English text from the standard:

```text
In general, implementations SHOULD ACK as many received packets as can fit into the ACK record; if space is limited, implementations SHOULD favor including records which have not yet been acknowledged.
```

The first clause is covered by collecting received handshake records into an ACK list. The second clause requires a policy decision when the list cannot include everything.

## Relevant Source Code

`wolfssl-master/src/dtls13.c:742`

```c
if (ssl->dtls13Rtx.seenRecordsCount >= DTLS13_ACK_MAX_RECORDS) {
    return 0; /* list full, silently drop */
}
```

`wolfssl-master/src/dtls13.c:766`

```c
/* Cap the ACK list to prevent word16 overflow in
 * Dtls13GetAckListLength and bound memory consumption */
if (count >= DTLS13_MAX_ACK_RECORDS) {
    WOLFSSL_MSG("DTLS 1.3 ACK list full, dropping record");
    return 0;
}
```

`wolfssl-master/src/dtls13.c:2603`

```c
int Dtls13WriteAckMessage(WOLFSSL* ssl,
    Dtls13RecordNumber* recordNumberList, word16 recordsCount, word32* length)
```

ACK serialization writes the current linked list as `(epoch, sequence_number)` pairs. No field records whether a listed record has already been acknowledged to the peer.

## Implementation Behavior

The implementation maintains a bounded, sorted ACK list. It prevents duplicates and avoids length overflow. When the list reaches the maximum, insertion of an additional received record returns success with no list change.

Implemented part:

```text
collect received handshake record numbers
sort and deduplicate them
serialize as DTLS 1.3 ACK RecordNumber entries
cap the encoded list size safely
```

Missing part:

```text
track whether a record has already been acknowledged to the peer
when space is limited, prefer not-yet-acknowledged records over already-acknowledged records
```

## Inconsistency Reason

RFC 9147 uses SHOULD, so this is not an absolute wire-format failure. However, the implementation does not make the required preference decision at all. The current behavior is bounded-list drop by insertion order and numeric position, not priority by previous ACK coverage.

## Runtime Evidence

Command run from `wolfssl-master`:

```text
..\build\wolfssl-dtls13-audit-tests\tests\unit.test.exe -test_dtls13_ack_order -test_dtls13_ack_overflow -test_dtls13_ack_dup_write_counter -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Relevant log: `phase2_wolfssl_builtin_dtls13_tests.log`

The focused ACK overflow test passed. Its assertions show the current behavior:

```text
one over limit - must be silently dropped
seenRecordsCount remains DTLS13_ACK_MAX_RECORDS
```

This confirms memory-safe overflow behavior, but also confirms the absence of replacement or priority handling.

## Impact

Under heavy ACK-list pressure, a newly received handshake record may be omitted from ACK coverage even if older entries were already acknowledged. That can delay peer retransmission convergence and increase unnecessary retransmissions in lossy or reordered networks.

## Fix Direction

Add ACK coverage metadata or an ACK-generation policy that can distinguish records already sent in earlier ACKs from records not yet acknowledged. When the list is full, retain or replace entries so records without prior ACK coverage are preferred.
