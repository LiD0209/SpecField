# DTLS 1.3 RequestConnectionId and NewConnectionId Are Not Implemented

## Summary

RFC 9147 defines DTLS 1.3 post-handshake Connection ID update messages: `NewConnectionId` and `RequestConnectionId`. `RequestConnectionId` carries `num_cids`, and endpoints should respond by sending `NewConnectionId` with `usage = cid_spare` containing the requested number of CIDs, subject to the excessive-request exception.

wolfSSL has DTLS CID extension support and can place a negotiated/static CID into the DTLS 1.3 unified header. However, the audited source does not define `request_connection_id(9)`, `new_connection_id(10)`, `RequestConnectionId`, `NewConnectionId`, `num_cids`, `ConnectionIdUsage`, `cid_spare`, or `cid_immediate` in the protocol state machine.

This confirms IDs 145 and 146 as **unsatisfied**. The two findings have the same root cause.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Appendix A.2 defines the DTLS 1.3 handshake message body alternatives:

```text
case request_connection_id: RequestConnectionId;
case new_connection_id:     NewConnectionId;
```

RFC 9147 Section 9, `Connection ID Updates`, defines the dynamic CID update structures:

```text
enum {
    cid_immediate(0), cid_spare(1), (255)
} ConnectionIdUsage;
```

```text
struct {
    ConnectionId cids<0..2^16-1>;
    ConnectionIdUsage usage;
} NewConnectionId;
```

```text
struct {
  uint8 num_cids;
} RequestConnectionId;
```

The same section defines the `num_cids` response behavior:

```text
num_cids:  The number of CIDs desired.
```

```text
Endpoints SHOULD respond to RequestConnectionId by sending a
NewConnectionId with usage "cid_spare" containing num_cids CIDs as
soon as possible.
```

It also allows fewer CIDs for excessive requests:

```text
An endpoint MAY handle requests which it considers excessive by responding with a
NewConnectionId message containing fewer than num_cids CIDs,
including no CIDs at all.
```

These requirements are runtime handshake-message behavior. Static CID negotiation through the `connection_id` extension is not enough to satisfy them.

## Code Behavior

### Static CID Support Exists

wolfSSL has a static/extension-driven CID model. In `D:\project\wolfssl-master\wolfssl\internal.h`, `CIDInfo` stores only current transmit and receive CID pointers:

```c
typedef struct CIDInfo {
    ConnectionID* tx;
    ConnectionID* rx;
    byte negotiated : 1;
} CIDInfo;
```

In `D:\project\wolfssl-master\src\dtls.c`, the connection_id extension parser configures the negotiated CID:

```c
int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input, word16 length,
    byte isRequest)
```

The public API can enable and set an initial receive CID:

```c
int wolfSSL_dtls_cid_use(WOLFSSL* ssl)
```

```c
int wolfSSL_dtls_cid_set(WOLFSSL* ssl, unsigned char* cid, unsigned int size)
```

In `D:\project\wolfssl-master\src\dtls13.c`, the DTLS 1.3 unified header can carry a negotiated transmit CID:

```c
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
{
    ...
    *flags |= DTLS13_CID_BIT;
    ...
}
```

and the parser can check the received CID:

```c
static int Dtls13UnifiedHeaderParseCID(WOLFSSL* ssl, byte flags,
    const byte* input, word16 inputSize, word16* idx)
```

This implemented part supports fixed CIDs negotiated/configured before use.

### Dynamic CID Handshake Types Are Missing

In `D:\project\wolfssl-master\wolfssl\internal.h`, `enum HandShakeType` contains regular TLS/DTLS messages such as `client_hello`, `server_hello`, `session_ticket`, `certificate_request`, `finished`, and `key_update`:

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

There is no `request_connection_id = 9` and no `new_connection_id = 10`.

### Dispatcher Has No RequestConnectionId/NewConnectionId Branch

In `D:\project\wolfssl-master\src\tls13.c`, `DoTls13HandShakeMsgType` dispatches supported handshake messages. It has branches for `certificate_request`, `session_ticket`, `client_hello`, `finished`, and `key_update`, among others:

```c
case certificate_request:
    ret = DoTls13CertificateRequest(ssl, input, inOutIdx, size);
    break;
```

```c
case session_ticket:
    ret = DoTls13NewSessionTicket(ssl, input, inOutIdx, size);
    break;
```

```c
case key_update:
    ret = DoTls13KeyUpdate(ssl, input, inOutIdx, size);
    break;
```

The switch has no `case request_connection_id` and no `case new_connection_id`. Unknown message types fall to:

```c
default:
    WOLFSSL_MSG("Unknown handshake message type");
    ret = UNKNOWN_HANDSHAKE_TYPE;
    break;
```

Therefore a peer sending RFC 9147 dynamic CID update messages has no message parser or state transition to reach.

### No num_cids or cid_spare State Machine

Repository-wide source checks in the protocol files found no `num_cids`, no `ConnectionIdUsage`, no `cid_spare`, and no `cid_immediate` symbols. That means the implementation cannot:

| RFC 9147 behavior | wolfSSL audited behavior |
|---|---|
| Parse `RequestConnectionId.num_cids` | No `RequestConnectionId` type or parser |
| Respond with `NewConnectionId` | No `NewConnectionId` sender |
| Set `usage = cid_spare` | No `ConnectionIdUsage` or `cid_spare` symbol |
| Copy or apply requested `num_cids` | No `num_cids` state or response loop |
| Maintain spare receiver-provided CID list | `CIDInfo` only stores current `tx` and `rx` pointers |

### Existing API Rejects In-Connection CID Changes

In `D:\project\wolfssl-master\src\dtls.c`, `wolfSSL_dtls_cid_set` rejects attempts to set a receive CID after one already exists:

```c
if (cidInfo->rx != NULL) {
    WOLFSSL_MSG("wolfSSL doesn't support changing the CID during a "
                "connection");
    return WOLFSSL_FAILURE;
}
```

The extension parser also rejects changing the CID on a rehandshake:

```c
/* For now we don't support changing the CID on a rehandshake */
if (cidSz != info->tx->length ||
        XMEMCMP(info->tx->id, input + OPAQUE8_LEN, cidSz) != 0)
    return DTLS_CID_ERROR;
```

This is consistent with static CID support, but it is the opposite of the dynamic CID update model required by RFC 9147 Section 9.

### Built-in Tests Cover Static CID Only

`D:\project\wolfssl-master\tests\api\test_dtls.c` includes `test_dtls13_basic_connection_id`. It enables CID, configures a client and server CID with `wolfSSL_dtls_cid_set`, checks that CID bytes appear in DTLS 1.3 traffic, and checks that wrong CIDs are rejected.

That test is useful, but it only proves static negotiated/configured CID behavior. It does not send `RequestConnectionId`, parse `num_cids`, generate `NewConnectionId`, or process `usage = cid_spare`.

## Runtime Evidence

### Compiled C Harness

I added a focused C harness:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_dynamic_cid_145_146_source_check.c
```

Build command run from `D:\project`:

```text
D:\LLVM\bin\clang.exe D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_dynamic_cid_145_146_source_check.c -o D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_dynamic_cid_145_146_source_check.exe
```

The executable was run and its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_dynamic_cid_145_146_source_check.log
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

This is a compiled source-behavior harness. It verifies both sides of the finding: static CID support exists, while the dynamic CID message and `num_cids`/`cid_spare` state machine is absent.

## Inconsistency

| ID | Requirement component | wolfSSL behavior | Result |
|---:|---|---|---|
| 145 | Implement `RequestConnectionId` / `NewConnectionId` dynamic CID messages | Static CID extension and unified-header CID support exist, but no handshake message enum, parser, sender, or dispatcher branch exists | Unsatisfied |
| 146 | Parse `num_cids` and respond with `NewConnectionId(usage = cid_spare)` containing requested CIDs, subject to excessive-request handling | No `num_cids`, `ConnectionIdUsage`, `cid_spare`, spare CID list, or response generation path exists | Unsatisfied |

## Root Cause

wolfSSL implements RFC 9146-style CID negotiation and DTLS 1.3 unified-header CID encoding, but it does not implement the RFC 9147 post-handshake dynamic CID update protocol.

The current model is:

```text
connection_id extension / local API -> current tx/rx CID -> unified header CID
```

The missing RFC 9147 model is:

```text
RequestConnectionId(num_cids)
    -> NewConnectionId(cids, usage = cid_spare)
    -> spare receiver-provided CID list / activation policy
```

Because the handshake types and state machine are absent, the `num_cids` copy and `cid_spare` behavior cannot occur.

## Impact

Peers that rely on DTLS 1.3 dynamic CID provisioning or CID rotation cannot interoperate with this wolfSSL path. Static CID operation may work, but runtime requests for new spare CIDs and receiver-provided CID queue management are unavailable.

## Suggested Fix

Add RFC 9147 Section 9 dynamic CID support:

| Area | Required work |
|---|---|
| Handshake types | Add `request_connection_id = 9` and `new_connection_id = 10` |
| Parser | Parse `RequestConnectionId.num_cids` and `NewConnectionId.cids/usage` |
| Sender | Generate `NewConnectionId` responses with `usage = cid_spare` |
| State | Maintain spare receiver-provided CID lists and outstanding request state |
| Validation | Enforce negotiated-CID preconditions and unexpected-message alerts |
| Tests | Cover zero, normal, excessive `num_cids`, `cid_spare`, and absent-CID-negotiation cases |
