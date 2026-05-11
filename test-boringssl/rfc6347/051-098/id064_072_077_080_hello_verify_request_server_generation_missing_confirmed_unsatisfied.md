# HelloVerifyRequest Server Generation Path Is Missing

## Summary

BoringSSL can parse HelloVerifyRequest as a DTLS client and resend ClientHello with the received cookie, but the audited tree has no server-side HelloVerifyRequest generation path. Requirements that depend on sending HVR records are therefore unsatisfied.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc6347>

Section: RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures

Original English excerpt:

```text
The client MUST retransmit the ClientHello with the cookie added.
```

The relevant requirement is that a DTLS implementation support the stated DTLS 1.2 behavior under the condition captured by the extracted rule.

## Relevant Source Code

```c++
ssl/handshake_client.cc:517
static bool handle_hello_verify_request(SSL_HANDSHAKE *hs,
                                        const SSLMessage &msg) {
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    return false;
  }
  if (!hs->dtls_cookie.CopyFrom(cookie)) {
    return false;
  }
  hs->received_hello_verify_request = true;
  if (!hs->transcript.Init()) {
    return false;
  }
  return ssl_add_client_hello(hs);
}

ssl/handshake_server.cc:334
      {TLSEXT_TYPE_cookie, false},

ssl/dtls_record.cc:500
  DTLSRecordNumber record_number = write_epoch->next_record;
  if (!record_number.HasNext()) {
    return false;
  }
...
  write_epoch->next_record = record_number.Next();
```

## Implementation Behavior

The client receive path reads server_version and cookie, stores the cookie, resets the transcript, and sends another ClientHello. The server file does not construct DTLS1_MT_HELLO_VERIFY_REQUEST, and the focused probe also found no SSL_OP_COOKIE_EXCHANGE-like API. Outgoing DTLS records use the ordinary next_record counter, not a copied ClientHello sequence number for HVR.

## Inconsistency Reason

The standard's HVR sequence-copying and HVR server_version requirements only apply when a server sends HelloVerifyRequest. BoringSSL has the client half but not the server send path, so it cannot satisfy the server-side requirements for record sequence copying, version selection, or multiple cookie-exchange duplicate avoidance.

## Runtime Evidence

The focused probe `repro_dtls12_hvr_static_probe.exe` was compiled and run successfully. See `repro_dtls12_hvr_static_probe.log`.

## Impact

A BoringSSL DTLS server cannot use RFC 6347 stateless cookie exchange to avoid creating state before peer address validation. This may matter for deployments expecting the RFC 6347 HelloVerifyRequest DoS mitigation.

## Fix Direction

Add an explicit DTLS 1.2 server cookie-exchange feature only if BoringSSL wants to support this mitigation: server cookie callbacks/API, HelloVerifyRequest serialization, record sequence copying from ClientHello, client retransmission tests, and transcript exclusion tests. Otherwise document that server-side HelloVerifyRequest is intentionally unsupported.
