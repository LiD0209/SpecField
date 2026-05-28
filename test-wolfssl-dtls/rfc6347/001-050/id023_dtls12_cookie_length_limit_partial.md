# DTLS 1.2 client only retains HelloVerifyRequest cookies up to 32 bytes

## Summary
wolfSSL implements the DTLS 1.2 cookie exchange, but its client-side storage for the cookie received in `HelloVerifyRequest` is limited to `MAX_COOKIE_LEN`, which is 32 bytes. RFC 6347 represents the DTLS 1.2 cookie as an 8-bit-length opaque vector, so a conforming server can send a cookie larger than 32 bytes and up to 255 bytes.

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc6347

RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures

```text
The server responds with a HelloVerifyRequest containing a stateless cookie. The client retransmits the ClientHello with the cookie added. The server verifies the cookie before continuing. Cookies SHOULD be generated as HMAC(Secret, Client-IP, Client-Parameters). When the server changes the Secret value, it SHOULD retain the previous value for a limited period and accept cookies generated with either secret.
```

RFC 6347 also defines the DTLS 1.2 `ClientHello.cookie` and `HelloVerifyRequest.cookie` fields as `opaque cookie<0..2^8-1>`. Taken together, the syntax allows a cookie length from 0 to 255 bytes, and the client is required to retransmit the `ClientHello` with the cookie received from `HelloVerifyRequest`.

## Relevant Source Code
```c
src/internal.c:31357
if (cookieSz <= MAX_COOKIE_LEN) {
    XMEMCPY(ssl->arrays->cookie, input + *inOutIdx, cookieSz);
    ssl->arrays->cookieSz = cookieSz;
}

wolfssl/internal.h:1572
MAX_COOKIE_LEN = 32
```

The retransmitted DTLS `ClientHello` uses the saved value:

```c
src/internal.c:31225
byte cookieSz = ssl->arrays->cookieSz;

src/internal.c:31227
output[idx++] = cookieSz;

src/internal.c:31229
XMEMCPY(&output[idx], ssl->arrays->cookie, cookieSz);
```

Server-side context:

```c
src/dtls.c:284
if (ch->cookie.size != DTLS_COOKIE_SZ)
    return 0;
```

## Implementation Behavior
When wolfSSL parses a DTLS `HelloVerifyRequest` as a client, it reads the one-byte cookie length but only copies the cookie into `ssl->arrays->cookie` when `cookieSz <= MAX_COOKIE_LEN`. Since `MAX_COOKIE_LEN` is 32, a syntactically valid 33..255 byte cookie is skipped rather than retained. The later `ClientHello` retransmission uses `ssl->arrays->cookieSz`, so a skipped larger cookie is not echoed back to the server.

The server-side `DTLS_COOKIE_SZ` check is a narrower point. wolfSSL generates and verifies its own fixed-size HMAC cookie, so requiring that size for cookies returned to its own server is mainly an implementation cookie-format policy. It is useful context, but the clearer compliance and interoperability gap is on the client side: wolfSSL cannot preserve and retransmit a larger cookie sent by another conforming DTLS 1.2 server.

## Inconsistency Reason
RFC 6347 permits DTLS 1.2 cookie values up to 255 bytes and requires the client to retransmit `ClientHello` with the received cookie added. wolfSSL's client-side receive path retains only cookies up to 32 bytes. Therefore, a valid `HelloVerifyRequest` carrying a 33..255 byte cookie can be processed without the cookie being saved, preventing the following `ClientHello` from carrying the required cookie.

This is a partial compliance issue rather than a complete absence of cookie support: wolfSSL handles its own 20-byte or 32-byte generated cookies, but it is not interoperable with conforming peers that choose larger DTLS 1.2 cookies within the RFC vector limit.

## Runtime Evidence
The verification script confirms `MAX_COOKIE_LEN = 32`, the guarded copy in `DoHelloVerifyRequest`, and the fixed-size server cookie comparison. The first two facts are the primary evidence for this issue.

## Impact
wolfSSL clients can fail to complete the DTLS 1.2 cookie exchange with servers that send legal `HelloVerifyRequest` cookies larger than 32 bytes.

## Fix Direction
Increase the client-side cookie storage path to preserve peer cookies up to the RFC 6347 vector limit of 255 bytes, then retransmit exactly the received cookie in the next `ClientHello`. The server can still keep its own fixed HMAC cookie format if desired, but the client parser should not silently drop valid peer cookies above 32 bytes.
