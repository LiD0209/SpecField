# DTLS 1.3 Dynamic Connection ID Update Semantics Are Missing

## Summary

RFC 9147 defines dynamic DTLS 1.3 Connection ID update messages. A peer can send `NewConnectionId` with `ConnectionIdUsage = cid_immediate` or `cid_spare`, and endpoints should maintain receiver-provided CIDs in the order they were provided.

wolfSSL has static DTLS CID support: it can negotiate a CID, store one current TX/RX CID pair, add the current CID to DTLS 1.3 unified record headers, and validate the current RX CID. It does not implement the RFC 9147 dynamic CID update messages or the required CID list/queue semantics.

This confirms IDs 031, 032, and 033 as **not satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Section 9, `Connection ID Updates`, defines the dynamic CID messages:

```text
enum { cid_immediate(0), cid_spare(1), (255) } ConnectionIdUsage;
opaque ConnectionId<0..2^8-1>;
struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;
```

It defines the `cid_immediate` behavior:

```text
If usage is set to "cid_immediate", then one of the new CIDs MUST be used immediately for all future records.
```

It defines spare CID handling:

```text
If it is set to "cid_spare", then either an existing or new CID MAY be used.
```

It also defines receiver-provided CID ordering and excess spare-CID handling:

```text
Endpoints SHOULD use receiver-provided CIDs in the order they were provided.
```

```text
Implementations which receive more spare CIDs than they wish to maintain MAY simply discard any extra CIDs.
```

Appendix A.2 and A.4 list the corresponding handshake message types and structures:

```text
request_connection_id(9), /* New */
new_connection_id(10),    /* New */
```

```text
struct { uint8 num_cids; } RequestConnectionId;
```

These requirements depend on parsing and serializing `RequestConnectionId` / `NewConnectionId`, storing multiple receiver-provided CIDs, and selecting future record CIDs according to `ConnectionIdUsage`.

## Code Behavior

### Handshake Types Do Not Include Dynamic CID Messages

In `wolfssl/internal.h`, `enum HandShakeType` includes normal TLS/DTLS handshake types through `key_update`, but not `request_connection_id(9)` or `new_connection_id(10)`:

```c
enum HandShakeType {
    hello_request        =   0,
    client_hello         =   1,
    server_hello         =   2,
    hello_verify_request =   3,    /* DTLS addition */
    session_ticket       =   4,
    end_of_early_data    =   5,
    hello_retry_request  =   6,
    encrypted_extensions =   8,
    certificate          =  11,
    ...
    key_update           =  24,
    ...
};
```

This means the product handshake type table lacks the RFC 9147 dynamic CID handshake message identifiers.

### TLS 1.3 / DTLS 1.3 Dispatch Has No Dynamic CID Branch

In `src/tls13.c`, the handshake validation/dispatch logic has `case key_update`, but no `case request_connection_id` or `case new_connection_id` branch:

```c
case key_update:
    /* Valid on both sides. */
    ...
    break;
```

The focused probe also searched the product source and tests for `RequestConnectionId`, `NewConnectionId`, `ConnectionIdUsage`, `cid_immediate`, and `cid_spare`; no dynamic CID message implementation was found.

### CID State Stores Only Current TX/RX CID

In `wolfssl/internal.h`, `CIDInfo` stores only one current TX CID, one current RX CID, and a negotiated flag:

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

There is no spare-CID list, no receiver-provided CID queue, no usage metadata, and no outstanding `NewConnectionId` / `RequestConnectionId` state.

### Existing API Explicitly Rejects In-Connection CID Changes

In `src/dtls.c`, the extension parse path rejects changing the CID on rehandshake:

```c
/* For now we don't support changing the CID on a rehandshake */
if (cidSz != info->tx->length ||
        XMEMCMP(info->tx->id, input + OPAQUE8_LEN, cidSz) != 0)
    return DTLS_CID_ERROR;
```

The public setter also rejects changing the RX CID during a connection:

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

These checks are the opposite of dynamic CID update support.

### DTLS 1.3 Record Layer Supports Static Current CID

In `src/dtls13.c`, `Dtls13AddCID` can add the current negotiated TX CID to the unified header:

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

and `Dtls13UnifiedHeaderParseCID` validates the current RX CID:

```c
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
    const byte* input, word16 inputSize, word16* idx)
```

This confirms that wolfSSL implements static CID record handling, but not the dynamic RFC 9147 update messages required for IDs 031-033.

## Runtime Evidence

### Compiled C Harness

I added and compiled a focused C source-check harness:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_031_033_source_check.c
```

Build command run from `D:\project`:

```text
clang D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_031_033_source_check.c -o D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_031_033_source_check.exe
```

The executable was run and its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_031_033_source_check.log
```

Observed output:

```text
PASS CIDInfo stores only current tx/rx CID pointers
PASS Handshake enum lacks request_connection_id
PASS Handshake enum lacks new_connection_id
PASS No RequestConnectionId implementation in checked protocol files
PASS No NewConnectionId implementation in checked protocol files
PASS No ConnectionIdUsage/cid_immediate/cid_spare symbols
PASS Existing API rejects changing CID during a connection
PASS DTLS extension parser rejects changing CID on rehandshake
PASS Static DTLS 1.3 CID record support exists
RESULT confirmed: static CID support exists, dynamic RFC9147 CID update messages and queues are absent
```

The harness is compiled and run as a native executable. It directly reads the local wolfSSL product source and verifies that static CID support exists while the dynamic CID update messages and queue/usage symbols are absent.

### Executable Source Probe

I also ran a focused executable Python probe against the local source tree:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\focused_dynamic_cid_031_033_probe.py
```

Saved log:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\focused_dynamic_cid_031_033_probe.log
```

Observed output:

```text
CIDInfo stores only tx/rx current CIDs: PASS
Handshake enum has no request_connection_id: PASS
Handshake enum has no new_connection_id: PASS
TLS13 handshake dispatcher has no RequestConnectionId/NewConnectionId branch: PASS
No ConnectionIdUsage symbols: PASS
No cid_immediate symbol: PASS
No cid_spare symbol: PASS
No too_many_cids_requested alert symbol: PASS
DTLS CID API rejects changing CID during a connection: PASS
DTLS extension parser rejects changing CID on rehandshake: PASS
DTLS 1.3 record layer can add current negotiated CID: PASS
DTLS 1.3 record layer validates current RX CID: PASS
RESULT: confirmed static CID support exists, dynamic RFC9147 CID update messages and queues are absent
```

Existing saved wolfSSL unit-test evidence in this directory shows that static CID tests pass:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\phase2_wolfssl_builtin_dtls13_tests.log
```

Relevant excerpt:

```text
test_dtls13_basic_connection_id : passed
test_wolfSSL_dtls_cid_parse     : passed
```

This turn did not rerun the full wolfSSL `unit.test.exe`, but it did compile and run the focused C harness above with `clang`.

## Inconsistency

| RFC 9147 requirement component | wolfSSL behavior |
|---|---|
| `NewConnectionId` message with `ConnectionIdUsage` | No handshake type, parser, serializer, or dispatcher found |
| `cid_immediate` must switch future records to one of the new CIDs immediately | No `cid_immediate` symbol or CID switch state exists |
| `cid_spare` supports existing/new spare CID use | No spare CID list or usage metadata exists |
| Receiver-provided CIDs should be used in provided order | No receiver-provided CID queue exists |
| Extra spare CIDs may be discarded by local policy | No dynamic spare-CID receive path exists |
| Static negotiated CID in record headers | Implemented |

## Root Cause

wolfSSL implements static DTLS CID negotiation and current-CID record-layer processing, but not RFC 9147 dynamic CID update messages.

The product state model has only current TX/RX CID pointers. It lacks `RequestConnectionId`, `NewConnectionId`, `ConnectionIdUsage`, spare CID storage, receiver-provided CID ordering, and future-record CID migration logic.

## Impact

Peers that rely on RFC 9147 dynamic CID update behavior will not interoperate with wolfSSL for these paths:

| ID | Missing behavior | Impact |
|---:|---|---|
| 031 | `cid_immediate` immediate switch | Future records cannot be migrated to a newly provided CID as required |
| 032 | spare CID list management | Spare CIDs cannot be retained, selected, or discarded by policy |
| 033 | receiver-provided CID queue | CIDs cannot be used in the order provided by the peer |

This is a protocol feature-completeness gap, not evidence of memory corruption.

## Suggested Fix

To satisfy RFC 9147, wolfSSL would need to add:

| Required change | Expected effect |
|---|---|
| `request_connection_id(9)` and `new_connection_id(10)` handshake types | Dynamic CID messages can be parsed and serialized |
| `ConnectionIdUsage` parser and serializer | `cid_immediate` and `cid_spare` semantics can be represented |
| Receiver-provided CID queue | CIDs can be used in peer-provided order |
| Spare CID list management | Extra spare CIDs can be retained or discarded by policy |
| Record-layer CID switch logic | `cid_immediate` can affect all future records |
| Regression tests | Static CID and dynamic CID update behavior are separated and covered |
