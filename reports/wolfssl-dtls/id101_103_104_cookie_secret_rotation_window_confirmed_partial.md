# DTLS 1.3 Cookie Secret Rotation Window and Cookie Lifetime Policy Are Application-Managed

## Summary

This report covers IDs 101, 103, and 104.

wolfSSL implements the main DTLS 1.3 HelloRetryRequest cookie mechanism: the server can send a cookie extension, the cookie is HMAC-protected with a server secret, and an invalid cookie is rejected. However, the audited implementation stores and verifies cookies with one active `tls13CookieSecret` only. It does not provide a built-in previous/current secret transition window, key identifier, two-secret verification path, or cookie timestamp/expiration policy.

The finding is therefore confirmed as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant sections: RFC 9147 Section 5.1, `Denial-of-Service Countermeasures`, and Section 5.3, `ClientHello Format`.

Relevant original English text from RFC 9147:

```text
The server can defend against this attack by changing the secret value frequently, thus invalidating those cookies.
```

```text
If the server wishes to allow legitimate clients to handshake through the transition (e.g., a client received a cookie with Secret 1 and then sent the second ClientHello after the server has changed to Secret 2), the server can have a limited window during which it accepts both secrets.
```

```text
[RFC7296] suggests adding a key identifier to cookies to detect this case. An alternative approach is simply to try verifying with both secrets.
```

```text
It is RECOMMENDED that servers implement a key rotation scheme that allows the server to manage keys with overlapping lifetimes.
```

```text
Alternatively, the server can store timestamps in the cookie and reject cookies that were generated outside a certain interval of time.
```

```text
If a server receives a ClientHello with an invalid cookie, it MUST terminate the handshake with an "illegal_parameter" alert.
```

The rotation-window and timestamp language is not an unconditional "MUST" for every implementation strategy. It is a recommended or alternative server-side policy for managing cookie validity during secret changes. This is why the result is partial rather than fully unsatisfied.

## Relevant Source Code

### Single HRR Cookie Secret Field

`wolfssl-master\wolfssl\internal.h:5024`

```c
buffer          tls13CookieSecret;     /* HRR cookie secret */
```

The audited structure has one HRR cookie secret field. No companion previous-secret field such as `tls13CookieSecretPrev`, `oldCookieSecret`, or similar was found.

### Cookie Generation Uses the Single Secret

`wolfssl-master\src\tls13.c:3632`

```c
int CreateCookieExt(const WOLFSSL* ssl, byte* hash, word16 hashSz,
                    TLSX** exts, byte cipherSuite0, byte cipherSuite)
```

`wolfssl-master\src\tls13.c:3648`

```c
if (ssl->buffers.tls13CookieSecret.buffer == NULL ||
        ssl->buffers.tls13CookieSecret.length == 0) {
    WOLFSSL_MSG("Missing DTLS 1.3 cookie secret");
    return COOKIE_ERROR;
}
```

`wolfssl-master\src\tls13.c:3692`

```c
ret = wc_HmacSetKey(cookieHmac, cookieType,
                    ssl->buffers.tls13CookieSecret.buffer,
                    ssl->buffers.tls13CookieSecret.length);
```

`CreateCookieExt` constructs cookie data from the ClientHello hash and selected negotiation values, then protects it with HMAC under `tls13CookieSecret`. In DTLS mode it also binds the cookie to the peer address.

### Cookie Verification Uses the Same Single Secret

`wolfssl-master\src\tls13.c:6844`

```c
int TlsCheckCookie(const WOLFSSL* ssl, const byte* cookie, word16 cookieSz)
```

`wolfssl-master\src\tls13.c:6852`

```c
if (ssl->buffers.tls13CookieSecret.buffer == NULL ||
        ssl->buffers.tls13CookieSecret.length == 0) {
    WOLFSSL_MSG("Missing DTLS 1.3 cookie secret");
    return COOKIE_ERROR;
}
```

`wolfssl-master\src\tls13.c:6883`

```c
ret = wc_HmacSetKey(cookieHmac, cookieType,
                    ssl->buffers.tls13CookieSecret.buffer,
                    ssl->buffers.tls13CookieSecret.length);
```

`wolfssl-master\src\tls13.c:6908`

```c
if (ConstantCompare(cookie + cookieSz, mac, macSz) != 0) {
    WOLFSSL_ERROR_VERBOSE(HRR_COOKIE_ERROR);
    return HRR_COOKIE_ERROR;
}
```

This verifies the received cookie with the current secret. There is no second verification attempt with a previous secret, no key identifier branch, and no timestamp/expiration check in this function.

### DTLS ClientHello Path Calls the Cookie Verifier

`wolfssl-master\src\dtls.c:263`

```c
static int CheckDtlsCookie(const WOLFSSL* ssl, WolfSSL_CH* ch,
                           byte isTls13, byte* cookieGood)
```

`wolfssl-master\src\dtls.c:278`

```c
ret = TlsCheckCookie(ssl, ch->cookieExt.elements + OPAQUE16_LEN,
        (word16)(ch->cookieExt.size - OPAQUE16_LEN));
```

The DTLS 1.3 stateless ClientHello path routes the cookie extension to `TlsCheckCookie`.

### Public API Replaces the Single Secret

`wolfssl-master\src\tls13.c:14484`

```c
int wolfSSL_send_hrr_cookie(WOLFSSL* ssl, const unsigned char* secret,
                            unsigned int secretSz)
```

`wolfssl-master\src\tls13.c:14512`

```c
if (ssl->buffers.tls13CookieSecret.buffer != NULL) {
    ForceZero(ssl->buffers.tls13CookieSecret.buffer,
              ssl->buffers.tls13CookieSecret.length);
    XFREE(ssl->buffers.tls13CookieSecret.buffer,
          ssl->heap, DYNAMIC_TYPE_COOKIE_PWD);
}
```

`wolfssl-master\src\tls13.c:14544`

```c
XMEMCPY(ssl->buffers.tls13CookieSecret.buffer, secret, secretSz);
```

`wolfssl-master\src\tls13.c:14546`

```c
ssl->options.sendCookie = 1;
```

This API allows an application to configure or regenerate the HRR cookie secret. When the secret length changes, the old buffer is zeroed and freed before the new one is installed. The code does not preserve the old secret for an overlap window.

## Existing wolfSSL Test Coverage

`wolfssl-master\tests\api\test_tls13.c:5468`

```c
/* Test that a corrupted HRR cookie HMAC is rejected with HRR_COOKIE_ERROR. */
int test_tls13_hrr_bad_cookie(void)
```

`wolfssl-master\tests\api\test_tls13.c:5507`

```c
ssl_s->buffers.tls13CookieSecret.buffer[
    ssl_s->buffers.tls13CookieSecret.length - 1] ^= 0xFF;
```

`wolfssl-master\tests\api\test_tls13.c:5516`

```c
WC_NO_ERR_TRACE(HRR_COOKIE_ERROR));
```

wolfSSL has a unit test proving that a cookie fails when the active server-side secret no longer verifies it. That supports the current-secret integrity path, but it also demonstrates the absence of an automatic old-secret acceptance window in the tested behavior.

## Runtime Evidence

Compiled source-behavior harness:

`test-wolfssl-dtls\rfc9147\101-150\repro_cookie_secret_window_101_103_104_source_check.c`

Build command:

```powershell
& 'D:\LLVM\bin\clang.exe' 'test-wolfssl-dtls\rfc9147\101-150\repro_cookie_secret_window_101_103_104_source_check.c' -o 'test-wolfssl-dtls\rfc9147\101-150\repro_cookie_secret_window_101_103_104_source_check.exe'
```

Run command:

```powershell
& 'test-wolfssl-dtls\rfc9147\101-150\repro_cookie_secret_window_101_103_104_source_check.exe' *> 'test-wolfssl-dtls\rfc9147\101-150\repro_cookie_secret_window_101_103_104_source_check.log'
```

Observed result:

```text
Conclusion: PASS - source behavior confirms IDs 101/103/104 are partially satisfied: single-secret HMAC cookies exist, but no built-in dual-secret window or cookie timestamp/expiration policy was found.
```

Important selected assertions from the same log:

```text
PASS single HRR cookie secret field                             contains "buffer          tls13CookieSecret;"
PASS TlsCheckCookie verifies with the same single secret        contains "ssl->buffers.tls13CookieSecret.buffer"
PASS TlsCheckCookie rejects bad MAC                             contains "return HRR_COOKIE_ERROR;"
PASS no previous cookie secret field                            does not contain "tls13CookieSecretPrev"
PASS no old cookie secret field                                 does not contain "oldCookieSecret"
PASS no both-secret verification wording                        does not contain "both secrets"
PASS CreateCookieExt has no timestamp                           does not contain "timestamp"
PASS TlsCheckCookie has no expiration                           does not contain "expiration"
```

This is a compiled and executed source-behavior check. It is not a full packet-level interoperability test because this local checkout does not contain a prebuilt wolfSSL library or test executable to link and run a complete DTLS 1.3 handshake scenario.

## Inconsistency Reason

Implemented behavior:

| Requirement area | wolfSSL behavior |
|---|---|
| DTLS 1.3 HRR cookie extension | Implemented through `CreateCookieExt` and the DTLS ClientHello cookie path. |
| Cookie integrity | Implemented with HMAC over cookie data using `tls13CookieSecret`. |
| Invalid cookie rejection | Implemented through `HRR_COOKIE_ERROR`. |
| Application-controlled secret | Implemented through `wolfSSL_send_hrr_cookie`. |

Missing or application-managed behavior:

| RFC 9147 policy area | wolfSSL audited behavior |
|---|---|
| Frequently changing cookie secret | Application can call `wolfSSL_send_hrr_cookie`, but wolfSSL does not provide a built-in rotation scheduler. |
| Limited transition window accepting both old and new secrets | No previous-secret storage and no two-secret verification loop were found. |
| Key identifier in cookie | No key-id field or verifier branch was found in the HRR cookie path. |
| Cookie timestamp and expiration interval | No timestamp/lifetime/expiration field or check was found in `CreateCookieExt` or `TlsCheckCookie`. |

Therefore, IDs 101, 103, and 104 are real partial-consistency findings: wolfSSL implements the basic cookie mechanism, but not the built-in overlapping-lifetime or timestamp-expiration policy described by RFC 9147 as a recommended/alternative server-side defense.

## Impact

Deployments using wolfSSL's default single active HRR cookie secret can reject stale cookies after a secret change, but legitimate clients that received a cookie before rotation may fail during the transition unless the application manages rotation carefully. Because the cookie does not carry a timestamp or key identifier in the audited path, built-in age-based rejection and old/new secret selection are not available.

## Suggested Fix Direction

Add an internal cookie-secret manager for DTLS 1.3 HRR cookies. A complete fix should include:

1. Current and previous cookie secrets with explicit activation and expiration times.
2. Cookie encoding that optionally includes a key identifier or timestamp.
3. Verification that accepts cookies generated by either valid secret during the overlap window.
4. Rejection of cookies outside the configured lifetime.
5. Unit tests for current-secret success, previous-secret transition success, expired-cookie rejection, and malformed key-id/timestamp rejection.
