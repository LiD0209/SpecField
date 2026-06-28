# DTLS 1.3 Dynamic Connection ID Request/Response Is Missing

## Summary

RFC 9147 defines post-handshake Connection ID update messages for DTLS 1.3: `RequestConnectionId` and `NewConnectionId`. After CID negotiation, a peer can request additional CIDs with `RequestConnectionId.num_cids`; the receiving endpoint should respond with `NewConnectionId` using `usage = cid_spare`, subject to the excessive-request exception.

wolfSSL implements static/negotiated DTLS CID support and can encode a configured CID in the DTLS 1.3 unified header. The audited source does not implement the RFC 9147 dynamic CID message types, parsers, senders, or spare-CID state needed for `RequestConnectionId` / `NewConnectionId`.

The core finding is therefore real. The precise interpretation is:

| Item | Meaning | Decision |
|---:|---|---|
| 145 | Excessive-request behavior is an RFC `MAY` exception: an endpoint may return fewer than requested CIDs, including zero | Missing because the whole dynamic CID response mechanism is absent; not an independent hard MUST violation |
| 146 | Normal `RequestConnectionId` handling is an RFC `SHOULD`: respond with `NewConnectionId(usage = cid_spare)` containing `num_cids` CIDs | Unsatisfied: there is no parser/handler for the request and no response path |

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Appendix A.2 defines two DTLS 1.3 handshake message types:

```text
request_connection_id(9),           /* New */
new_connection_id(10),              /* New */
```

and maps them to handshake bodies:

```text
case request_connection_id: RequestConnectionId;
case new_connection_id:     NewConnectionId;
```

RFC 9147 Section 9, "Connection ID Updates", defines the dynamic CID structures:

```text
enum {
    cid_immediate(0), cid_spare(1), (255)
} ConnectionIdUsage;

opaque ConnectionId<0..2^8-1>;

struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;

struct {
  uint8 num_cids;
} RequestConnectionId;
```

The normal response rule is:

```text
Endpoints SHOULD respond to RequestConnectionId by sending a
NewConnectionId with usage "cid_spare" containing num_cids CIDs as
soon as possible.
```

The excessive-request exception is optional behavior:

```text
An endpoint MAY handle requests which it considers excessive by responding with a
NewConnectionId message containing fewer than num_cids CIDs,
including no CIDs at all.
```

So static CID negotiation through the RFC 9146 `connection_id` extension is not enough to satisfy this behavior. The implementation needs post-handshake message handling and state for requested/spare CIDs.

## Relevant Source Code

`wolfssl-master/wolfssl/internal.h:6047` defines a single `ConnectionID` object:

```c
typedef struct ConnectionID {
    byte length;
    byte id[];
} ConnectionID;
```

`wolfssl-master/wolfssl/internal.h:6057` stores only current transmit and receive CID pointers:

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

`wolfssl-master/wolfssl/internal.h:6753` defines the handshake type enum. The values jump from `encrypted_extensions = 8` to `certificate = 11`; there is no `request_connection_id = 9` and no `new_connection_id = 10`:

```c
enum HandShakeType {
    hello_request        =   0,
    client_hello         =   1,
    server_hello         =   2,
    hello_verify_request =   3,
    session_ticket       =   4,
    end_of_early_data    =   5,
    hello_retry_request  =   6,
    encrypted_extensions =   8,
    certificate          =  11,
    certificate_request  =  13,
    certificate_verify   =  15,
    finished             =  20,
    key_update           =  24,
    message_hash         = 254,
    no_shake             = 255
};
```

`wolfssl-master/src/tls13.c:13548` rejects unexpected post-handshake messages after the handshake is done:

```c
if (ssl->options.handShakeState == HANDSHAKE_DONE &&
        type != session_ticket && type != certificate_request &&
        type != certificate && type != key_update && type != finished) {
    WOLFSSL_MSG("HandShake message after handshake complete");
    SendAlert(ssl, alert_fatal, unexpected_message);
    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
    return OUT_OF_ORDER_E;
}
```

`wolfssl-master/src/tls13.c:13579` dispatches supported TLS 1.3 handshake messages. It has no `case request_connection_id` or `case new_connection_id`; unknown message types fall through to `UNKNOWN_HANDSHAKE_TYPE`:

```c
case key_update:
    WOLFSSL_MSG("processing key update");
    ret = DoTls13KeyUpdate(ssl, input, inOutIdx, size);
    break;

default:
    WOLFSSL_MSG("Unknown handshake message type");
    ret = UNKNOWN_HANDSHAKE_TYPE;
    break;
```

`wolfssl-master/src/dtls.c:1264` implements the RFC 9146-style `connection_id` extension parser:

```c
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
```

`wolfssl-master/src/dtls.c:1307` explicitly rejects CID changes on rehandshake:

```c
/* For now we don't support changing the CID on a rehandshake */
if (cidSz != info->tx->length ||
        XMEMCMP(info->tx->id, input + OPAQUE8_LEN, cidSz) != 0)
    return DTLS_CID_ERROR;
```

`wolfssl-master/src/dtls.c:1370` exposes an API for setting an initial receive CID, but `wolfssl-master/src/dtls.c:1382` rejects setting a second one during the connection:

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

`wolfssl-master/src/dtls13.c:1170` and `wolfssl-master/src/dtls13.c:1192` implement DTLS 1.3 unified-header CID encoding and parsing for the currently configured CID:

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

```c
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
    const byte* input, word16 inputSize, word16* idx)
```

`wolfssl-master/tests/api/test_dtls13.c:685` covers static DTLS 1.3 CID behavior. It enables CID, sets one client CID and one server CID, and checks that those configured CIDs appear in traffic.

## Implementation Behavior

The implemented CID model is:

```text
connection_id extension / local API
    -> current tx/rx CID
    -> DTLS 1.3 unified-header CID bit and CID bytes
```

The RFC 9147 dynamic CID model that is missing is:

```text
RequestConnectionId(num_cids)
    -> parse requested CID count
    -> generate NewConnectionId(cids, usage = cid_spare)
    -> maintain spare receiver-provided CID list
    -> apply activation/discard policy
```

Repository-wide checks over the relevant protocol files found no implementation symbols for:

```text
RequestConnectionId
NewConnectionId
request_connection_id
new_connection_id
num_cids
ConnectionIdUsage
cid_spare
cid_immediate
too_many_cids_requested
```

Because these message types are not in the handshake enum or dispatcher, a peer's RFC 9147 dynamic CID message has no valid parser or state transition in this implementation.

## Inconsistency Reason

RFC 9147 requires DTLS 1.3 implementations that support CID updates to understand the `RequestConnectionId` / `NewConnectionId` handshake-message mechanism. In the normal case, an endpoint should respond to `RequestConnectionId.num_cids` with `NewConnectionId(usage = cid_spare)` carrying the requested number of CIDs.

wolfSSL only proves support for static or negotiated CID use:

| RFC 9147 behavior | wolfSSL behavior |
|---|---|
| Recognize handshake type `request_connection_id(9)` | Missing from `enum HandShakeType` |
| Recognize handshake type `new_connection_id(10)` | Missing from `enum HandShakeType` |
| Dispatch dynamic CID post-handshake messages | No dispatcher cases; unexpected post-handshake types are rejected |
| Parse `RequestConnectionId.num_cids` | No parser or field |
| Generate `NewConnectionId` | No sender |
| Set `usage = cid_spare` | No `ConnectionIdUsage` / `cid_spare` implementation |
| Maintain spare receiver-provided CID list | `CIDInfo` stores only current `tx` and `rx` |

The 145 finding should be read carefully. The RFC text for excessive requests is a `MAY`, so failing to implement that optional exception alone would not be a strict violation. Here it is still unsatisfied in the audit because the underlying `RequestConnectionId` / `NewConnectionId` mechanism does not exist at all.

The 146 finding is the main interoperability gap: there is no way for wolfSSL to parse `num_cids` and respond with `NewConnectionId(usage = cid_spare)`.

## Runtime Evidence

A focused source-check harness was already created:

```text
test-wolfssl-dtls/rfc9147/101-150/repro_dynamic_cid_145_146_source_check.c
```

The saved result is:

```text
test-wolfssl-dtls/rfc9147/101-150/repro_dynamic_cid_145_146_source_check.log
```

Observed output:

```text
PASS Static CID state stores only current tx/rx pointers
PASS Static DTLS CID extension parser exists
PASS DTLS 1.3 unified header CID support exists
PASS Built-in tests cover static DTLS 1.3 CID behavior
PASS Handshake enum lacks request_connection_id(9)
PASS Handshake enum lacks new_connection_id(10)
PASS TLS 1.3 dispatcher has no dynamic CID message cases
PASS Protocol source lacks RequestConnectionId/NewConnectionId implementations
PASS Protocol source lacks num_cids and cid_spare handling
PASS Protocol source lacks ConnectionIdUsage/cid_immediate handling
PASS Existing API rejects changing CID during a connection
PASS Extension parser rejects changing CID on rehandshake
RESULT confirmed: wolfSSL has static CID support, but no RFC9147 RequestConnectionId/NewConnectionId num_cids/cid_spare state machine
```

This is a compiled source-behavior check, not a packet-level interoperability test. It is still sufficient to confirm the source-level absence of the required dynamic CID state machine. A full runtime packet test was blocked in the existing audit environment because the local build did not provide an enabled DTLS 1.3/CID wolfSSL runtime binary.

## Impact

Static CID use can still work. Applications that only configure one negotiated CID and keep using it are not the affected case.

The affected case is DTLS 1.3 dynamic CID provisioning or CID rotation after the handshake. A peer that sends `RequestConnectionId` and expects `NewConnectionId(usage = cid_spare)` will not get RFC 9147-compliant handling from this wolfSSL path.

This can break interoperability with peers that rely on spare CIDs for path changes, NAT rebinding, address/port changes, or privacy-oriented CID rotation.

## Fix Direction

Add RFC 9147 Section 9 dynamic CID support:

| Area | Required work |
|---|---|
| Handshake types | Add `request_connection_id = 9` and `new_connection_id = 10` |
| Parser | Parse `RequestConnectionId.num_cids` and `NewConnectionId.cids/usage` |
| Sender | Generate `NewConnectionId` responses with `usage = cid_spare` |
| State | Maintain spare receiver-provided CID lists and outstanding request state |
| Validation | Enforce negotiated-CID preconditions and unexpected-message alerts |
| Excessive requests | Decide when to return fewer than `num_cids` CIDs or raise `too_many_cids_requested` |
| Tests | Cover zero, normal, excessive `num_cids`, `cid_spare`, and absent-CID-negotiation cases |
