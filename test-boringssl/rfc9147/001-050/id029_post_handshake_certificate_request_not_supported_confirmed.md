# Post-Handshake CertificateRequest Implicit ACK Is Not a Supported Product Path

## Summary

RFC 9147 lists the server's post-handshake `CertificateRequest` as a flight that can be implicitly acknowledged by the next responding flight. It also defines post-handshake client authentication as one of the DTLS 1.3 post-handshake message categories with its own reliability state machine.

BoringSSL does not implement this product path. The server explicitly never initiates post-handshake authentication, the post-handshake dispatcher accepts only `NewSessionTicket` and `KeyUpdate`, and the DTLS implicit ACK logic is limited to the main handshake. A post-handshake `CertificateRequest` is therefore not a supported path in BoringSSL.

The original JSON classification should not remain **satisfied** for ID 029. The correct audit classification depends on scope:

| Audit scope | Suggested classification |
|---|---|
| If RFC 9147 post-handshake `CertificateRequest` reliability semantics are required | Not satisfied |
| If unsupported optional post-handshake client authentication is excluded from scope | Not applicable |

In either scope, this item should not be used as evidence that BoringSSL satisfies post-handshake `CertificateRequest` implicit ACK behavior.

## Standard Requirement

RFC 9147, Section 7.1, "Sending ACKs":

```text
In general, flights MUST be ACKed unless they are implicitly
acknowledged.  In the present specification, the following flights
are implicitly acknowledged by the receipt of the next flight, which
generally immediately follows the flight:

1.  Handshake flights other than the client's final flight of the
    main handshake.

2.  The server's post-handshake CertificateRequest.

ACKs SHOULD NOT be sent for these flights unless the responding
flight cannot be generated immediately.  All other flights MUST be
ACKed.  In this case, implementations MAY send explicit ACKs for the
complete received flight even though it will eventually also be
implicitly acknowledged through the responding flight.
```

RFC 9147, Section 5.8.4, "State Machine Duplication for Post-Handshake Messages":

```text
DTLS 1.3 makes use of the following categories of post-handshake
messages:

1.  NewSessionTicket

2.  KeyUpdate

3.  NewConnectionId

4.  RequestConnectionId

5.  Post-handshake client authentication

Messages of each category can be sent independently, and reliability
is established via independent state machines, each of which behaves
as described in Section 5.8.1.  For example, if a server sends a
NewSessionTicket and a CertificateRequest message, two independent
state machines will be created.
```

The same section also states:

```text
Likewise, a server MAY send multiple CertificateRequest messages at
once without having completed earlier client authentication requests
before.
```

The expected product behavior, if this feature is implemented, is:

| Event | Expected behavior |
|---|---|
| Server sends post-handshake `CertificateRequest` | Create an independent post-handshake reliability state machine |
| Client can respond immediately | Response flight implicitly acknowledges the server's `CertificateRequest` |
| Client cannot respond immediately | Explicit ACK behavior applies as described by RFC 9147 |
| Multiple post-handshake `CertificateRequest` messages are sent | Reliability is tracked independently |

## Code Behavior

### Server Does Not Initiate Post-Handshake Authentication

In `ssl/handshake.cc`, BoringSSL explicitly states that a server does not initiate post-handshake authentication:

```cpp
if (ssl->server) {
  // The largest acceptable post-handshake message for a server is a
  // KeyUpdate. We will never initiate post-handshake auth.
  return 1;
}
```

Because the product server never initiates post-handshake authentication, there is no server path that sends a post-handshake `CertificateRequest` and waits for the client's responding flight.

### Post-Handshake Dispatcher Does Not Accept CertificateRequest

In `ssl/tls13_both.cc`, `tls13_post_handshake` handles client-side `NewSessionTicket` and either-side `KeyUpdate`:

```cpp
bool tls13_post_handshake(SSL *ssl, const SSLMessage &msg) {
  if (msg.type == SSL3_MT_NEW_SESSION_TICKET && !ssl->server) {
    return tls13_process_new_session_ticket(ssl, msg);
  }

  if (msg.type == SSL3_MT_KEY_UPDATE) {
    ssl->s3->key_update_count++;
    if (SSL_is_quic(ssl) || ssl->s3->key_update_count > kMaxKeyUpdates) {
      OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_KEY_UPDATES);
      ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
      return false;
    }

    return tls13_receive_key_update(ssl, msg);
  }

  ssl->s3->key_update_count = 0;

  ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_UNEXPECTED_MESSAGE);
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_MESSAGE);
  return false;
}
```

There is no `SSL3_MT_CERTIFICATE_REQUEST` branch. A post-handshake `CertificateRequest` received through this dispatcher follows the `SSL_R_UNEXPECTED_MESSAGE` path.

### DTLS Implicit ACK Logic Is Limited to the Main Handshake

In `ssl/d1_both.cc`, BoringSSL has DTLS 1.3 implicit ACK logic for the main handshake:

```cpp
if (SSL_in_init(ssl) && ssl_has_final_version(ssl) &&
    ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
  // During the handshake, if we receive any portion of the next flight, the
  // peer must have received our most recent flight. In DTLS 1.3, this is an
  // implicit ACK. See RFC 9147, Section 7.1.
  //
  // This only applies during the handshake. After the handshake, the next
  // message may be part of a post-handshake transaction. It also does not
  // apply immediately after the handshake. As a client, receiving a
  // KeyUpdate or NewSessionTicket does not imply the server has received
  // our Finished. The server may have sent those messages in half-RTT.
  implicit_ack = true;
}
```

The condition `SSL_in_init(ssl)` and the source comment both limit this logic to the main handshake. This block cannot be used as evidence that post-handshake `CertificateRequest` implicit ACK behavior is implemented.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\001-050\repro_dtls13_post_handshake_certificate_request_not_supported_linked_probe.cpp
```

CMake target:

```text
repro_dtls13_ph_certreq_probe
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\001-050 -B D:\project\SpecTrace\test-boringssl\rfc9147\001-050\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\001-050\build-linked-probe --config Release --target repro_dtls13_ph_certreq_probe
D:\project\SpecTrace\test-boringssl\rfc9147\001-050\build-linked-probe\Release\repro_dtls13_ph_certreq_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\001-050\repro_dtls13_post_handshake_certificate_request_not_supported_linked_probe.log
```

Observed output:

```text
linked BoringSSL DTLS_method successfully
ok: handshake.cc contains We will never initiate post-handshake auth
ok: handshake.cc contains The largest acceptable post-handshake message for a server is a
ok: handshake.cc contains KeyUpdate
ok: handshake.cc contains return 1;
ok: tls13_post_handshake contains SSL3_MT_NEW_SESSION_TICKET
ok: tls13_post_handshake contains SSL3_MT_KEY_UPDATE
ok: tls13_post_handshake contains SSL_R_UNEXPECTED_MESSAGE
ok: tls13_post_handshake does not contain SSL3_MT_CERTIFICATE_REQUEST
ok: DTLS implicit ACK block contains This only applies during the handshake
ok: DTLS implicit ACK block contains After the handshake, the next
ok: DTLS implicit ACK block contains post-handshake transaction
ok: DTLS implicit ACK block contains implicit_ack = true
RESULT: confirmed issue. BoringSSL does not implement DTLS/TLS 1.3 post-handshake CertificateRequest processing; post-handshake dispatch only accepts NewSessionTicket and KeyUpdate, so ID029 should not be classified as satisfied for CertificateRequest implicit acknowledgement.
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks the relevant product-source predicates for post-handshake authentication, post-handshake dispatch, and DTLS implicit ACK scope.

## Inconsistency

| RFC 9147 behavior being claimed | BoringSSL behavior |
|---|---|
| Server post-handshake `CertificateRequest` can be implicitly ACKed by the next flight | Product server never initiates post-handshake authentication |
| Post-handshake client authentication has an independent reliability state machine | No supported post-handshake `CertificateRequest` path was found |
| Post-handshake dispatcher should process supported post-handshake categories | Dispatcher handles `NewSessionTicket` and `KeyUpdate`, not `CertificateRequest` |
| Main-handshake implicit ACK logic proves post-handshake CertificateRequest behavior | It does not; the code explicitly limits this inference to the handshake |

The original "satisfied" classification appears to have generalized from BoringSSL's supported post-handshake messages and main-handshake ACK logic to a `CertificateRequest` path that is not implemented.

## Root Cause

BoringSSL does not implement post-handshake client authentication as a product feature. Because the server never sends post-handshake `CertificateRequest`, there is no corresponding DTLS 1.3 reliability state machine and no implicit ACK behavior to validate for that message.

The relevant distinction is:

| Implemented path | Not implemented path |
|---|---|
| `NewSessionTicket` post-handshake handling | Server-initiated post-handshake `CertificateRequest` |
| `KeyUpdate` post-handshake handling | Post-handshake client-auth reliability state machine |
| Main-handshake implicit ACK inference | Post-handshake `CertificateRequest` implicit ACK inference |

## Impact

This is primarily a classification and protocol-feature coverage issue.

| Impact area | Description |
|---|---|
| Audit accuracy | ID 029 should not be counted as a confirmed satisfied implementation of post-handshake `CertificateRequest` implicit ACK. |
| Feature coverage | BoringSSL does not provide the server-initiated post-handshake authentication path described by RFC 9147. |
| Interoperability | A peer expecting post-handshake `CertificateRequest` processing cannot rely on this BoringSSL product path. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as unsupported post-handshake `CertificateRequest` behavior being previously classified too broadly.

## Suggested Fix

The fix depends on the intended audit scope.

| Scope decision | Suggested action |
|---|---|
| Post-handshake client authentication is out of scope | Reclassify ID 029 as not applicable and document that BoringSSL does not implement the feature |
| RFC 9147 post-handshake `CertificateRequest` reliability semantics are required | Reclassify ID 029 as not satisfied |
| Product support is desired | Implement server-initiated post-handshake authentication, post-handshake `CertificateRequest` dispatch, independent DTLS reliability state, and implicit ACK behavior |

Regression coverage should include a DTLS 1.3 post-handshake `CertificateRequest` scenario only if BoringSSL intentionally adds product support for post-handshake client authentication.
