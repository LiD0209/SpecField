# DTLS 1.3 Connection ID Request and Response Are Not Implemented

## Summary

RFC 9147 defines DTLS 1.3 post-handshake messages for Connection ID management:

```text
RequestConnectionId
NewConnectionId
```

These messages are used after the `connection_id` extension has been negotiated. An endpoint may request spare CIDs with `RequestConnectionId.num_cids`, and the peer should respond with `NewConnectionId` messages using the `cid_spare` usage.

BoringSSL does not implement this DTLS 1.3 CID request/response state machine. The DTLS 1.3 record layer sends records with `C=0`, rejects records whose CID bit is set because CID was not negotiated, and the product source has no handlers or constants for `RequestConnectionId`, `NewConnectionId`, `num_cids`, `cid_spare`, or related alerts. This confirms RFC 9147 IDs 145 and 146 as **not satisfied** with the same root cause.

## Standard Requirement

RFC 9147, Section 5.2, "DTLS Handshake Message Format", adds two DTLS 1.3 handshake message types:

```text
enum {
    client_hello(1),
    server_hello(2),
    new_session_ticket(4),
    end_of_early_data(5),
    encrypted_extensions(8),
    request_connection_id(9),           /* New */
    new_connection_id(10),              /* New */
    certificate(11),
    certificate_request(13),
    certificate_verify(15),
    finished(20),
    key_update(24),
    message_hash(254),
    (255)
} HandshakeType;
```

The same section maps those message types to their message bodies:

```text
case request_connection_id: RequestConnectionId;
case new_connection_id:     NewConnectionId;
```

RFC 9147, Section 9, "Connection ID Updates", defines the expected CID update behavior:

```text
If the client and server have negotiated the "connection_id"
extension [RFC9146], either side can send a new CID that it wishes
the other side to use in a NewConnectionId message.
```

It defines `RequestConnectionId` as:

```text
struct {
  uint8 num_cids;
} RequestConnectionId;

num_cids:  The number of CIDs desired.
```

It also defines the expected response:

```text
Endpoints SHOULD respond to RequestConnectionId by sending a
NewConnectionId with usage "cid_spare" containing num_cids CIDs as
soon as possible.
```

And it limits the messages to negotiated-CID connections:

```text
Endpoints MUST NOT send either of these messages if they did not
negotiate a CID.  If an implementation receives these messages when
CIDs were not negotiated, it MUST abort the connection with an
"unexpected_message" alert.
```

The expected lifecycle is therefore:

| State | Expected behavior |
|---|---|
| CID extension not negotiated | `RequestConnectionId` and `NewConnectionId` must not be sent |
| CID message received without CID negotiation | Abort with `unexpected_message` |
| CID extension negotiated | Endpoint may request spare CIDs with `RequestConnectionId.num_cids` |
| Peer receives `RequestConnectionId` | Respond as soon as possible with `NewConnectionId` using `cid_spare` |
| Excessive CID requests | Apply RFC-defined request limiting and alert behavior |

## Code Behavior

### DTLS 1.3 Record Writer Forces C=0

In `ssl/dtls_record.cc`, BoringSSL writes DTLS 1.3 records with the CID bit cleared:

```cpp
// We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1 (length
// is present), which is a mask of 0x2c. The E E bits are the low-order two
// bits of the epoch.
out[0] = 0x2c | (epoch & 0x3);
```

This means the current DTLS 1.3 record writer does not encode a Connection ID.

### DTLS 1.3 Record Parser Rejects CID-Bit Records

In `ssl/dtls_record.cc`, BoringSSL rejects a DTLS 1.3 record whose CID bit is set:

```cpp
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

This is consistent with BoringSSL's current no-CID-negotiated state. It also shows that there is no negotiated CID state feeding the DTLS 1.3 record parser.

### CID Request and Update Messages Are Absent

The linked probe recursively scanned BoringSSL product source under `ssl/*.cc` and `ssl/*.h`. It found no product-code implementation markers for the RFC 9147 CID request/update state machine:

```text
RequestConnectionId
NewConnectionId
request_connection_id
new_connection_id
num_cids
cid_spare
too_many_cids_requested
SSL3_MT_REQUEST_CONNECTION_ID
SSL3_MT_NEW_CONNECTION_ID
```

The public SSL header also did not expose a public DTLS CID configuration marker such as:

```text
SSL_set_connection_id
connection_id
```

The absence is broader than a missing test case. Product code lacks CID negotiation, record-layer CID processing, post-handshake message constants, parsers, senders, and response state.

## Runner Coverage

The BoringSSL runner contains negative coverage for a DTLS 1.3 record header with the CID bit set:

```text
DTLS13RecordHeader-CIDBit
DTLS13RecordHeaderSetCIDBit
```

This verifies the current behavior that a CID-bit record is rejected when CID was not negotiated.

No runner test or helper was found for:

```text
RequestConnectionId
NewConnectionId
num_cids
cid_spare
too_many_cids_requested
```

Runner coverage therefore matches the implementation shape: it covers the negative "CID bit not negotiated" record-header behavior, but not the RFC 9147 Section 9 CID request/response state machine.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_cid_request_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\101-150 -B D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe --config Release --target repro_dtls13_cid_request_probe
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe\Release\repro_dtls13_cid_request_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_cid_request_probe.log
```

Observed output:

```text
linked BoringSSL probe: PASS
record behavior: DTLS 1.3 CID bit is rejected as not negotiated, and sent records force C=0
source behavior: no RequestConnectionId/NewConnectionId/num_cids state machine or handshake type support was found in ssl/*.cc or ssl/*.h
runner coverage: runner has DTLS13RecordHeader-CIDBit negative coverage, but no RequestConnectionId/NewConnectionId tests
conclusion: RFC 9147 IDs 145 and 146 are confirmed unsatisfied with the same root cause
```

The probe links against BoringSSL, creates a `DTLS_method()` context to confirm linkage, then scans the checked-out BoringSSL source tree for CID request/update implementation markers and runner coverage markers.

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Define and process `request_connection_id(9)` | No product handshake type or handler found |
| Define and process `new_connection_id(10)` | No product handshake type or handler found |
| Support `RequestConnectionId.num_cids` | No `num_cids` state machine found |
| Respond with `NewConnectionId` using `cid_spare` | No `cid_spare` implementation found |
| Reject CID update messages when CID was not negotiated | CID-bit records are dropped, but CID post-handshake message handling is absent |
| Encode DTLS 1.3 records with CID when negotiated | Sent DTLS 1.3 records force `C=0` |

The implementation therefore does not merely omit an optional response path. It lacks the underlying DTLS 1.3 CID negotiation and post-handshake CID message machinery needed for RFC 9147 Section 9.

## Root Cause

BoringSSL currently implements DTLS 1.3 records in a no-CID mode. The record writer hard-codes `C=0`, and the record parser rejects CID-bit records as not negotiated. Since there is no negotiated CID state, there is also no higher-level state machine for CID requests and updates.

This single root cause covers both IDs:

| ID | Reason |
|---|---|
| 145 | No DTLS 1.3 CID request state machine exists for `num_cids` |
| 146 | No `RequestConnectionId` handler exists |

## Impact

This is a protocol feature-completeness and conformance gap for DTLS 1.3 Connection ID support.

| Impact area | Description |
|---|---|
| CID support | BoringSSL cannot negotiate or use DTLS 1.3 Connection IDs in product code. |
| CID lifecycle | The implementation cannot request spare CIDs or respond with `NewConnectionId`. |
| Address mobility | CID-based association continuity and migration behavior are unavailable. |
| Interoperability | Peers expecting RFC 9147 Section 9 CID update messages cannot interoperate for this feature. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as absence of the DTLS 1.3 CID request/response feature.

## Suggested Fix

Implementing this part of RFC 9147 would require more than adding message constants.

| Required change | Expected effect |
|---|---|
| Implement RFC 9146 `connection_id` extension negotiation for DTLS | Creates negotiated CID state |
| Add DTLS 1.3 record-layer CID encode/decode | Allows records with `C=1` when negotiated |
| Add handshake type constants for `request_connection_id(9)` and `new_connection_id(10)` | Makes the wire messages recognizable |
| Add parsers and serializers for `RequestConnectionId` and `NewConnectionId` | Implements the message bodies |
| Track outstanding CID requests and `num_cids` limits | Supports correct request lifecycle and abuse limits |
| Implement `cid_spare` response behavior | Lets peers obtain spare CIDs as RFC 9147 describes |
| Add alerts for unnegotiated CID messages and excessive requests | Covers `unexpected_message` and `too_many_cids_requested` behavior |
| Add runner tests with negotiated CID | Pins request, response, rejection, and limit behavior |
