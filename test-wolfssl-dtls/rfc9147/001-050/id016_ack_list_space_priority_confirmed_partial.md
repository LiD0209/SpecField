# DTLS 1.3 ACK List Space-Limited Priority Is Incomplete

## Summary

RFC 9147 says implementations should ACK as many received packets as can fit in an ACK record, and when space is limited, they should favor records that have not yet been acknowledged. wolfSSL implements a bounded DTLS 1.3 ACK record-number list, sorting, duplicate suppression, ACK serialization, and overflow-safe rejection. The missing part is the RFC's space-limited priority policy.

When the ACK list is full, wolfSSL silently drops the new record number. The ACK list nodes store only `next`, `epoch`, and `seq`; there is no metadata for whether a record number has already been sent in a previous ACK, and no replacement policy that prefers not-yet-acknowledged records.

This confirms ID 016 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `7.1 ACK Message`

Original English requirement excerpt:

```text
In general, implementations SHOULD ACK as many received packets as can fit into the ACK record; if space is limited, implementations SHOULD favor including records which have not yet been acknowledged.
```

The first clause is about collecting as many record numbers as fit. The second clause requires a policy decision under ACK-list pressure: if not all record numbers can fit, the implementation should prefer records without prior ACK coverage.

## Code Behavior

### ACK RecordNumber State Has No Acknowledged Flag

In `wolfssl/internal.h`, each ACK-list node stores only a linked-list pointer, epoch, and sequence number:

```c
typedef struct Dtls13RecordNumber {
    struct Dtls13RecordNumber *next;
    w64wrapper epoch;
    w64wrapper seq;
} Dtls13RecordNumber;
```

The retransmission state stores a single list and count:

```c
Dtls13RecordNumber *seenRecords;
word16 seenRecordsCount;
```

There is no `already_acknowledged`, `sent_in_ack`, or equivalent metadata.

### Full ACK List Drops the New Record

In `src/dtls13.c`, `Dtls13RtxAddAck` returns success without insertion when the current list count reaches the configured limit:

```c
if (ssl->dtls13Rtx.seenRecordsCount >= DTLS13_ACK_MAX_RECORDS) {
#ifdef WOLFSSL_RW_THREADED
    wc_UnLockMutex(&ssl->dtls13Rtx.mutex);
#endif
    return 0; /* list full, silently drop */
}
```

The insertion loop also drops a record when the insertion position reaches the local cap:

```c
/* Cap the ACK list to prevent word16 overflow in
 * Dtls13GetAckListLength and bound memory consumption */
if (count >= DTLS13_MAX_ACK_RECORDS) {
    WOLFSSL_MSG("DTLS 1.3 ACK list full, dropping record");
#ifdef WOLFSSL_RW_THREADED
    wc_UnLockMutex(&ssl->dtls13Rtx.mutex);
#endif
    return 0;
}
```

This is memory-safe bounded-list behavior, but it is not a priority policy based on whether a record has already been acknowledged.

### ACK Writer Enforces the Maximum

`Dtls13WriteAckMessage` rejects an oversized ACK list:

```c
if (recordsCount > DTLS13_ACK_MAX_RECORDS)
    return BUFFER_E;
msgSz = (word16)(DTLS13_RN_SIZE * recordsCount);
```

This protects the ACK encoding. It does not provide replacement or prioritization when a new record arrives after the list is full.

### Built-In Test Confirms Drop-on-Full Behavior

In `tests/api/test_dtls.c`, `test_dtls13_ack_overflow` explicitly asserts the current behavior:

```c
/* Edge case 3: one over limit - must be silently dropped */
ExpectIntEQ(Dtls13RtxAddAck(ssl_c, w64From32(0, 0),
                w64From32(0, (word32)DTLS13_ACK_MAX_RECORDS)), 0);
ExpectIntEQ(ssl_c->dtls13Rtx.seenRecordsCount, DTLS13_ACK_MAX_RECORDS);
```

That test validates safe overflow behavior, not RFC 9147's preference for not-yet-acknowledged records.

## Runtime Evidence

### Compiled C Harness

I added and compiled a focused C harness:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_ack_list_016_overflow_priority.c
```

Build command run from `D:\project`:

```text
clang D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_ack_list_016_overflow_priority.c -o D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_ack_list_016_overflow_priority.exe
```

The executable was run and its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_ack_list_016_overflow_priority.log
```

Observed output:

```text
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS fill add returns success: got=0
PASS list reaches capacity: got=8
PASS duplicate at capacity returns success: got=0
PASS duplicate does not grow list: got=8
PASS new record at capacity returns success: got=0
PASS new record at capacity is not retained: got=0
PASS count remains capped: got=8
RESULT confirmed: bounded ACK list silently drops new records at capacity and carries no acknowledged-state priority metadata
```

The harness mirrors the relevant `Dtls13RtxAddAck` capacity behavior: when the list is full, a new record returns success but is not retained, and the node model has no acknowledged-state field that could prioritize not-yet-acknowledged records.

### Executable Source Probe

I also ran a focused source probe for ID 016:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\focused_ack_list_016_probe.py
```

Saved log:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\focused_ack_list_016_probe.log
```

Observed output:

```text
ACK RecordNumber node stores only next/epoch/seq: PASS
ACK list has bounded seenRecordsCount: PASS
Dtls13RtxAddAck drops immediately when seenRecordsCount reaches max: PASS
Dtls13RtxAddAck drops when insertion position count reaches max: PASS
Dtls13RtxAddAck suppresses duplicates but has no acknowledged-state replacement: PASS
ACK writer rejects recordsCount over DTLS13_ACK_MAX_RECORDS: PASS
Unit test asserts one-over-limit is silently dropped: PASS
Unit test covers overflow safety, not priority by unacknowledged status: PASS
RESULT: confirmed ACK list is bounded and silently drops new records at capacity without acknowledged/unacknowledged priority metadata
```

Existing saved wolfSSL unit-test evidence in this directory shows the built-in ACK overflow test passing:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\phase2_wolfssl_builtin_dtls13_tests.log
```

Relevant excerpt:

```text
test_dtls13_ack_order                              : passed
test_dtls13_ack_overflow                           : passed
```

This turn did not rerun the full wolfSSL `unit.test.exe`, but it did compile and run the focused C harness above with `clang`.

## Inconsistency

| RFC 9147 requirement component | wolfSSL behavior |
|---|---|
| ACK as many received packets as fit | Implemented with a bounded ACK list |
| Avoid duplicate ACK entries | Implemented |
| Bound ACK encoding size safely | Implemented |
| When space is limited, favor records not yet acknowledged | Not implemented |
| Track whether a record number was previously included in an ACK | No metadata found |
| Replace an already-acknowledged entry with a not-yet-acknowledged record when full | No replacement policy found |

## Root Cause

wolfSSL's DTLS 1.3 ACK list is modeled as a bounded sorted list of record numbers. That model tracks received record numbers, but not ACK coverage history.

Because the list has no "already acknowledged" state, the insertion path cannot distinguish an older entry that has already been sent in an ACK from a newly received record that has not yet been acknowledged. Once the list is full, the new record is dropped.

## Impact

This is a partial protocol-behavior gap, not a memory-safety issue.

Under heavy ACK-list pressure, a newly received handshake record may be omitted from ACK coverage even if older entries have already been acknowledged. This can delay peer retransmission convergence and increase unnecessary retransmissions in lossy or reordered networks.

## Suggested Fix

To better satisfy RFC 9147 Section 7.1, wolfSSL should add ACK coverage metadata or an ACK-generation policy that can distinguish:

| State | Expected policy |
|---|---|
| Record number not yet included in an ACK | Prefer retaining it when space is limited |
| Record number already included in a previous ACK | Prefer dropping or replacing it under pressure |

At minimum, the full-list insertion path should be able to replace an already-acknowledged entry with a newly received not-yet-acknowledged record.
