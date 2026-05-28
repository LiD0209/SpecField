# DTLS 1.2 cookie secret rotation lacks a previous-secret acceptance window

## Summary 误报

wolfSSL computes and validates DTLS 1.2 cookies with an HMAC secret, but changing the secret replaces the old value immediately.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc6347

RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures

```text
The server responds with a HelloVerifyRequest containing a stateless cookie. The client retransmits the ClientHello with the cookie added. The server verifies the cookie before continuing. Cookies SHOULD be generated as HMAC(Secret, Client-IP, Client-Parameters). When the server changes the Secret value, it SHOULD retain the previous value for a limited period and accept cookies generated with either secret.
```

以上英文原文要求实现不仅要有字段编码，还要满足对应的运行时语义。

## Relevant Source Code

```c
src/ssl.c:6338
if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
    ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
              ssl->buffers.dtlsCookieSecret.length);
    XFREE(ssl->buffers.dtlsCookieSecret.buffer,
          ssl->heap, DYNAMIC_TYPE_COOKIE_PWD);
}

src/dtls.c:225
ret = wc_HmacSetKey(&cookieHmac, DTLS_COOKIE_TYPE,
    ssl->buffers.dtlsCookieSecret.buffer,
    ssl->buffers.dtlsCookieSecret.length);

src/dtls.c:292
*cookieGood = ConstantCompare(ch->cookie.elements, ch->dtls12cookie,
                              DTLS_COOKIE_SZ) == 0;
```

## Implementation Behavior

wolfSSL_DTLS_SetCookieSecret frees and replaces the current dtlsCookieSecret buffer. CreateDtls12Cookie and CheckDtlsCookie compute and compare a cookie only with that current secret.

## Inconsistency Reason

RFC 6347 says that when the server changes its Secret value, it should retain the previous value for a limited period and accept cookies generated with either value. wolfSSL implements the HMAC cookie construction but not the transition-window membership check.

## Runtime Evidence

The verification script checks that only dtlsCookieSecret is maintained and no previous/old secret window is present in the DTLS 1.2 cookie path.

## Impact

Clients that respond with a cookie minted immediately before server-side secret rotation may be forced into another HelloVerifyRequest round.

## Fix Direction

Add a previous cookie secret slot with a bounded lifetime and check incoming cookies against both current and previous secrets during the transition window.
