# DTLSHandshake Body Lacks Dynamic CID Message Branches

## Summary

RFC 9147 extends the DTLS 1.3 handshake body selection with two DTLS-specific dynamic Connection ID messages: `request_connection_id` and `new_connection_id`.

wolfSSL implements the ordinary TLS 1.3 / DTLS 1.3 handshake body dispatch path. It parses DTLS handshake headers, passes the body to the TLS 1.3 handshake dispatcher, and handles common message types such as `ClientHello`, `ServerHello`, `CertificateRequest`, `Certificate`, `Finished`, `NewSessionTicket`, and `KeyUpdate`.

The dynamic CID alternatives are not implemented. There is no `request_connection_id(9)` or `new_connection_id(10)` handshake type, no `RequestConnectionId` or `NewConnectionId` body parser/serializer, and no branch in the handshake dispatcher. This confirms ID 028 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Section 5.7, `Handshake Protocol`, defines the `DTLSHandshake` body as a selection over `msg_type`:

```text
select (msg_type) {
    case client_hello:          ClientHello;
    case server_hello:          ServerHello;
    case end_of_early_data:     EndOfEarlyData;
    case encrypted_extensions:  EncryptedExtensions;
    case certificate_request:   CertificateRequest;
    case certificate:           Certificate;
    case certificate_verify:    CertificateVerify;
    case finished:              Finished;
    case new_session_ticket:    NewSessionTicket;
    case key_update:            KeyUpdate;
    case request_connection_id: RequestConnectionId;
    case new_connection_id:     NewConnectionId;
} body;
```

Appendix A.2 lists the DTLS 1.3 handshake message type additions:

```text
request_connection_id(9), /* New */
new_connection_id(10),    /* New */
```

Appendix A.4 defines the corresponding CID message structures:

```text
struct { uint8 num_cids; } RequestConnectionId;
```

```text
struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;
```

The requirement is therefore not only a generic handshake parser. A complete DTLS 1.3 `body` implementation needs dispatch entries and message handling for the dynamic CID body alternatives.

## Code Behavior

### Handshake Type Table Omits Dynamic CID Types

In `D:\project\wolfssl-master\wolfssl\internal.h`, `enum HandShakeType` includes ordinary TLS and DTLS handshake values, including `key_update`, but it does not include values 9 or 10 for `request_connection_id` and `new_connection_id`:

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
    server_key_exchange  =  12,
    certificate_request  =  13,
    server_hello_done    =  14,
    certificate_verify   =  15,
    client_key_exchange  =  16,
    finished             =  20,
    certificate_status   =  22,
    key_update           =  24,
    ...
};
```

Because the symbolic message types are missing, the product code has no named entry point for the RFC 9147 dynamic CID handshake bodies.

### DTLS 1.3 Handshake Framing Exists

In `D:\project\wolfssl-master\src\dtls13.c`, `_Dtls13HandshakeRecv` parses the DTLS handshake header and then forwards the message type and body to the TLS 1.3 handshake dispatcher:

```c
ret = GetDtlsHandShakeHeader(ssl, input, &idx, &handshakeType,
    &messageLength, &fragOff, &fragLength, size);
```

```c
ret = DoTls13HandShakeMsgType(ssl, input, &idx, handshakeType,
    messageLength, size);
```

This confirms the implemented part of the requirement: DTLS handshake message framing and body dispatch infrastructure exists.

### TLS 1.3 / DTLS 1.3 Dispatcher Handles Ordinary Bodies Only

In `D:\project\wolfssl-master\src\tls13.c`, `DoTls13HandShakeMsgType` dispatches ordinary TLS 1.3 body cases:

```c
case server_hello:
    WOLFSSL_MSG("processing server hello");
    ret = DoTls13ServerHello(ssl, input, inOutIdx, size, &type);
    break;

case encrypted_extensions:
    WOLFSSL_MSG("processing encrypted extensions");
    ret = DoTls13EncryptedExtensions(ssl, input, inOutIdx, size);
    break;

case certificate_request:
    WOLFSSL_MSG("processing certificate request");
    ret = DoTls13CertificateRequest(ssl, input, inOutIdx, size);
    break;

case session_ticket:
    WOLFSSL_MSG("processing new session ticket");
    ret = DoTls13NewSessionTicket(ssl, input, inOutIdx, size);
    break;
```

The same function also handles `client_hello`, `certificate`, `certificate_verify`, `finished`, and `key_update`:

```c
case key_update:
    WOLFSSL_MSG("processing key update");
    ret = DoTls13KeyUpdate(ssl, input, inOutIdx, size);
    break;
```

The default path rejects unknown handshake types:

```c
default:
    WOLFSSL_MSG("Unknown handshake message type");
    ret = UNKNOWN_HANDSHAKE_TYPE;
    break;
```

There is no `case request_connection_id` and no `case new_connection_id`.

### Static CID Support Exists, But It Is Not Dynamic CID Body Handling

wolfSSL has static DTLS CID support. In `D:\project\wolfssl-master\wolfssl\internal.h`, CID state stores one current TX CID and one current RX CID:

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

In `D:\project\wolfssl-master\src\dtls13.c`, record-layer code can add and parse the current negotiated CID:

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
```

```c
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
    const byte* input, word16 inputSize, word16* idx)
```

However, this is record-layer handling of a current negotiated CID. It is not an implementation of `RequestConnectionId`, `NewConnectionId`, `ConnectionIdUsage`, `cid_immediate`, or `cid_spare`.

The public CID setter also explicitly rejects changing the RX CID after one has already been configured:

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

That behavior is consistent with static CID support, not RFC 9147 dynamic CID body handling.

## Runtime Evidence

### Compiled C Harness

I added and compiled a focused C source-check harness:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_body_028_source_check.c
```

Build command run from `D:\project`:

```text
clang D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_body_028_source_check.c -o D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_body_028_source_check.exe
```

The executable was run and its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\repro_dynamic_cid_body_028_source_check.log
```

Observed output:

```text
PASS HandshakeType enum has ordinary TLS 1.3 body types
PASS HandshakeType enum lacks request_connection_id
PASS HandshakeType enum lacks new_connection_id
PASS DTLS handshake receive path forwards body to TLS13 dispatcher
PASS TLS13 dispatcher handles ordinary body cases
PASS TLS13 dispatcher has no request_connection_id branch
PASS TLS13 dispatcher has no new_connection_id branch
PASS Static DTLS CID record support exists
RESULT confirmed: ordinary DTLSHandshake body handling exists, dynamic CID body branches are absent
```

The harness is compiled and run as a native executable. It directly reads the local wolfSSL product source and verifies both implemented behavior and missing dynamic CID body branches.

### Executable Source Probe

I also ran a focused executable source probe against the local wolfSSL tree:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\focused_dynamic_cid_body_028_probe.py
```

Saved output:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\001-050\focused_dynamic_cid_body_028_probe.log
```

Observed result:

```text
HandshakeType enum exists: PASS
HandshakeType enum includes normal TLS 1.3 messages: PASS
HandshakeType enum lacks request_connection_id(9): PASS
HandshakeType enum lacks new_connection_id(10): PASS
DTLS 1.3 handshake receive path exists: PASS
TLS 1.3 handshake dispatcher handles ordinary body cases: PASS
TLS 1.3 dispatcher has no dynamic CID body branch: PASS
Repository has no RequestConnectionId implementation: PASS
Repository has no NewConnectionId implementation: PASS
Repository has no ConnectionIdUsage implementation: PASS
Static DTLS CID support exists: PASS
CID state is current tx/rx, not a dynamic CID body queue: PASS
Existing API rejects changing CID during a connection: PASS
RESULT: confirmed partial satisfaction for RFC9147 DTLSHandshake.body: normal body cases exist, request_connection_id/new_connection_id branches are absent
```

This turn did not rerun the full wolfSSL `unit.test.exe`, but it did compile and run the focused C harness above with `clang`.

## Inconsistency

| RFC 9147 `DTLSHandshake.body` component | wolfSSL behavior |
|---|---|
| Ordinary body alternatives such as `ClientHello`, `ServerHello`, `CertificateRequest`, `Certificate`, `Finished`, `NewSessionTicket`, and `KeyUpdate` | Implemented in `DoTls13HandShakeMsgType` |
| DTLS handshake header parsing and body forwarding | Implemented in `_Dtls13HandshakeRecv` |
| `request_connection_id: RequestConnectionId` | Missing handshake type, parser, serializer, and dispatcher branch |
| `new_connection_id: NewConnectionId` | Missing handshake type, parser, serializer, and dispatcher branch |
| Static negotiated CID in DTLS records | Implemented |
| Dynamic CID body/state-machine behavior | Not implemented |

The issue is therefore accurately classified as **partial**: the generic and ordinary handshake body machinery exists, but the RFC 9147 dynamic CID body alternatives are absent.

## Root Cause

wolfSSL's DTLS 1.3 implementation reuses the TLS 1.3 handshake dispatcher and adds DTLS handshake framing around it. The implementation also has static CID record-layer support.

RFC 9147's dynamic CID messages require additional handshake type values, body parsing, body serialization, state validation, CID list management, and future-record CID selection. Those pieces are not present in the source tree. Unknown dynamic CID handshake message types would fall through to `UNKNOWN_HANDSHAKE_TYPE`.

## Impact

A peer that sends RFC 9147 dynamic CID handshake messages cannot interoperate with wolfSSL on this path. Ordinary DTLS 1.3 handshakes and static CID record handling may still work, but dynamic CID update messages will not be parsed or processed.

For ID 028 specifically, this means the `body` selection in RFC 9147 is not complete in wolfSSL: common body alternatives are implemented, while `request_connection_id` and `new_connection_id` are not.

## Suggested Fix

To fully satisfy the RFC 9147 body selection, wolfSSL would need to add:

| Required change | Expected effect |
|---|---|
| `request_connection_id(9)` and `new_connection_id(10)` in `enum HandShakeType` | The DTLS 1.3 message type table matches RFC 9147 |
| `RequestConnectionId` parser and serializer | `request_connection_id` body can be received and sent |
| `NewConnectionId` parser and serializer | `new_connection_id` body can be received and sent |
| `ConnectionIdUsage` support | `cid_immediate` and `cid_spare` semantics can be represented |
| Dispatcher branches in `DoTls13HandShakeMsgType` | Dynamic CID messages are routed to implementation code |
| State-machine and ACK/retransmission tests | Dynamic CID messages are covered as DTLS 1.3 handshake messages |
