# DTLS 1.2 Renegotiation message_seq Behavior Is Only Partially Supported

## Summary

RFC 6347 defines DTLS handshake messages with an explicit `message_seq` field. For the first message in a handshake the value starts at 0, and for a rehandshake the RFC example says the server's HelloRequest uses `message_seq = 0` and the following ServerHello uses `message_seq = 1`.

BoringSSL implements the initial DTLS handshake sequencing machinery. The handshake write and read counters start at 0, and `dtls1_init_message` writes `handshake_write_seq` into the handshake header. However, BoringSSL does not support DTLS renegotiation/rehandshake at all. Caller-initiated renegotiation is rejected, and the DTLS record path treats post-CCS handshake messages as unsupported renegotiation attempts except for a retransmitted Finished special case.

This confirms IDs 053 and 054 as **partially satisfied** with the same root cause.

## Standard Requirement

RFC 6347 explains why handshake messages carry an explicit sequence number:

```text
In DTLS, each handshake message is assigned a specific sequence
number within that handshake.  When a peer receives a handshake
message, it can quickly determine whether that message is the next
message it expects.  If it is, then it processes it.  If not, it
queues it for future handling once all previous messages have been
received.
```

The DTLS handshake header includes `message_seq`:

```text
struct {
  HandshakeType msg_type;
  uint24 length;
  uint16 message_seq;                               // New field
  uint24 fragment_offset;                           // New field
  uint24 fragment_length;                           // New field
  ...
} Handshake;
```

RFC 6347 states the sequencing rule:

```text
The first message each side transmits in each handshake always has
message_seq = 0.  Whenever each new message is generated, the
message_seq value is incremented by one.
```

And it gives the renegotiation/rehandshake example:

```text
rehandshake, this implies that the HelloRequest will have message_seq
= 0 and the ServerHello will have message_seq = 1.  When a message is
retransmitted, the same message_seq value is used.
```

The RFC also describes rehandshake state-machine transitions:

```text
When the server desires a rehandshake, it transitions from the
FINISHED state to the PREPARING state to transmit the HelloRequest.
When the client receives a HelloRequest, it transitions from FINISHED
to PREPARING to transmit the ClientHello.
```

The expected behavior is:

| State | Expected behavior |
|---|---|
| Initial handshake | First message from each side uses `message_seq = 0` |
| New handshake message | Increment `message_seq` by 1 |
| Retransmission | Reuse the same `message_seq` |
| Rehandshake/renegotiation | HelloRequest would use `message_seq = 0`, ServerHello would use `message_seq = 1` |

## Code Behavior

### Initial DTLS Handshake message_seq Is Implemented

In `ssl/internal.h`, BoringSSL keeps explicit handshake sequence counters:

```cpp
  uint16_t handshake_write_seq = 0;
  uint16_t handshake_read_seq = 0;
```

In `ssl/d1_both.cc`, `dtls1_init_message` writes the current write sequence into the handshake header:

```cpp
bool dtls1_init_message(const SSL *ssl, CBB *cbb, CBB *body, uint8_t type) {
  if (!CBB_init(cbb, 64) ||                                   //
      !CBB_add_u8(cbb, type) ||                               //
      !CBB_add_u24(cbb, 0 /* length (filled in later) */) ||  //
      !CBB_add_u16(cbb, ssl->d1->handshake_write_seq) ||      //
      !CBB_add_u24(cbb, 0 /* offset */) ||                    //
      !CBB_add_u24_length_prefixed(cbb, body)) {
    return false;
  }
```

After a new outgoing handshake message is added, BoringSSL increments the counter:

```cpp
    ssl->d1->handshake_write_seq++;
    if (ssl->d1->handshake_write_seq == 0) {
      ssl->d1->handshake_write_overflow = true;
    }
```

This satisfies the initial-handshake sequencing mechanism.

### DTLS Renegotiation Is Unsupported

In `ssl/ssl_lib.cc`, caller-initiated renegotiation is rejected:

```cpp
int SSL_renegotiate(SSL *ssl) {
  // Caller-initiated renegotiation is not supported.
  if (!ssl->s3->renegotiate_pending) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return 0;
  }
```

In `include/openssl/ssl.h`, the public API documentation states:

```cpp
// There is no support in BoringSSL for initiating renegotiations as a client
// or server.
```

In `ssl/d1_pkt.cc`, the post-CCS DTLS handshake path says that renegotiations are unsupported:

```cpp
    // Parse the first fragment header to determine if this is a pre-CCS or
    // post-CCS handshake record. DTLS resets handshake message numbers on each
    // handshake, so renegotiations and retransmissions are ambiguous.
```

```cpp
    // Otherwise, this is a pre-CCS handshake message from an unsupported
    // renegotiation attempt. Fall through to the error path.
```

So the RFC 6347 rehandshake example with HelloRequest/ServerHello sequencing is not reachable in BoringSSL product behavior.

### Runner Confirms the Same Limitation

In `ssl/test/runner/conn.go`, the runner notes:

```go
// In DTLS, renegotiation resets the message sequence numbers.
```

But in `ssl/test/runner/renegotiation_tests.go`, the test suite still records the product limitation:

```go
// We do not support renegotiation in DTLS, even if enabled.
```

This confirms that the test infrastructure knows the RFC sequencing rule, but the product path rejects renegotiation.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_renegotiation_message_seq_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe --config Release --target repro_dtls12_renegotiation_message_seq_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\build-linked-probe\Release\repro_dtls12_renegotiation_message_seq_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\051-098\repro_dtls12_renegotiation_message_seq_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
LINK SSL_new: PASS
Initial DTLS handshake write seq is 0: PASS
Initial DTLS handshake read seq is 0: PASS
Caller-initiated renegotiation returns failure: PASS
SSL_renegotiate error: function should not have been called
DTLS message_seq is written from handshake_write_seq: PASS
DTLS initial handshake seq fields default to zero: PASS
DTLS post-handshake record path marks renegotiation unsupported: PASS
Public docs say initiating renegotiation is unsupported: PASS
SSL_renegotiate rejects caller-initiated renegotiation: PASS
Runner notes DTLS renegotiation resets message sequence numbers: PASS
Runner tests document DTLS renegotiation not supported by BoringSSL: PASS

EXIT_CODE: 0
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks the source predicates for initial handshake sequencing, renegotiation rejection, DTLS post-CCS unsupported-renegotiation handling, and runner documentation.

## Inconsistency

| RFC 6347 behavior | BoringSSL behavior |
|---|---|
| Initial handshake messages start at `message_seq = 0` | Implemented |
| Each new handshake message increments `message_seq` | Implemented |
| Retransmissions reuse the same `message_seq` | Implemented |
| Rehandshake HelloRequest would have `message_seq = 0` | Not reachable because DTLS renegotiation is unsupported |
| Rehandshake ServerHello would have `message_seq = 1` | Not reachable because DTLS renegotiation is unsupported |

The product implementation therefore satisfies the generic handshake sequencing mechanics, but not the renegotiation-specific RFC example behavior.

## Root Cause

BoringSSL intentionally does not support DTLS renegotiation/rehandshake.

| Area | Behavior |
|---|---|
| Initial DTLS handshake sequencing | Implemented |
| Caller-initiated renegotiation | Rejected |
| DTLS post-CCS handshake records | Treated as unsupported renegotiation attempts |
| RFC 6347 rehandshake `message_seq` example | Not reachable in product behavior |

That is why IDs 053 and 054 are partial rather than fully satisfied: the ordinary message sequence mechanism exists, but the rehandshake-specific scenario required to exercise the RFC example does not.

## Impact

This is a DTLS renegotiation feature gap, not a general message-sequence implementation failure.

| Impact area | Description |
|---|---|
| Protocol scope | The RFC's renegotiation `message_seq` examples cannot be exercised by product code. |
| Product capability | BoringSSL does not support initiating DTLS renegotiation. |
| Test coverage | Runner documentation confirms the limitation rather than providing renegotiation support. |
| Initial handshake correctness | Preserved; the issue is limited to the renegotiation scope. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as unsupported DTLS renegotiation, which makes the rehandshake-specific `message_seq` behavior absent.

## Suggested Fix

To support the RFC 6347 rehandshake example, BoringSSL would need to implement DTLS renegotiation/rehandshake support, including the corresponding state transitions and handshake sequencing.

| Required change | Expected effect |
|---|---|
| Add DTLS renegotiation support | Makes the RFC rehandshake sequence reachable |
| Model HelloRequest/ServerHello rehandshake sequencing | Allows the `message_seq = 0` / `message_seq = 1` example |
| Preserve retransmission semantics | Keeps `message_seq` stable across retransmits |
| Add runner coverage for DTLS renegotiation | Pins the expected RFC 6347 rehandshake behavior |
