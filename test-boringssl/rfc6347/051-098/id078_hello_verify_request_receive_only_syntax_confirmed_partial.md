# HelloVerifyRequest Syntax Support Is Receive-Only

## Summary

BoringSSL parses HelloVerifyRequest syntax correctly on the client side, but it does not generate the message as a server, so the extracted structure rule is only partially implemented.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc6347>

Section: RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures

Original English excerpt:

```text
This message contains a stateless cookie.
```

The relevant requirement is that a DTLS implementation support the stated DTLS 1.2 behavior under the condition captured by the extracted rule.

## Relevant Source Code

```c++
ssl/handshake_client.cc:524
  CBS hello_verify_request = msg.body, cookie;
  uint16_t server_version;
  if (!CBS_get_u16(&hello_verify_request, &server_version) ||
      !CBS_get_u8_length_prefixed(&hello_verify_request, &cookie) ||
      CBS_len(&hello_verify_request) != 0) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    ssl_send_alert(ssl, SSL3_AL_FATAL, SSL_AD_DECODE_ERROR);
    return false;
  }
```

## Implementation Behavior

The parser enforces the expected uint16 server_version followed by uint8-length-prefixed cookie and no trailing data. The missing half is serialization by a DTLS server.

## Inconsistency Reason

The syntax rule is satisfied for client receipt but not for full message support. Because BoringSSL cannot emit HVR, this is confirmed partial rather than fully satisfied.

## Runtime Evidence

The focused probe `repro_dtls12_hvr_static_probe.exe` was compiled and run successfully. See `repro_dtls12_hvr_static_probe.log`.

## Impact

Interoperability with servers that send HVR is supported on the client side. Server-side deployments do not get HVR syntax generation or the associated cookie exchange mitigation.

## Fix Direction

Either keep the receive-only support documented, or add server-side HVR serialization and tests if full RFC 6347 HVR support is desired.
