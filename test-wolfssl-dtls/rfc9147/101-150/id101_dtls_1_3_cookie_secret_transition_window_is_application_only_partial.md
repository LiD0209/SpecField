# DTLS 1.3 Cookie Secret Transition Window Is Application-Only

## Summary
This item is confirmed as partially satisfied. wolfSSL implements the main related DTLS 1.3 path, but this audit could not prove the full conditional behavior required by the extracted RFC 9147 rule.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 5.3, ClientHello Format; Section 5.2.1, Denial-of-Service Countermeasures

Original English normative text:

```text
If the server wishes to allow legitimate clients to handshake through the transition (e.g., a client received a cookie with Secret 1 and then sent the second ClientHello after the server has changed to Secret 2), the server can have a limited window during which it accepts both secrets. ... An alternative approach is simply to try verifying with both secrets.
```

Extracted requirement:

```text
Condition: During a limited transition window after server secret rotation.
Action: may be accepted if verifiable with both secrets
```

## Relevant Source Code
- `src/tls13.c:14083`
- `src/tls13.c:6620`
- `src/tls13.c:6547`
- `src/tls13.c:7145`
- `src/tls13.c:7111`
- `src/internal.c:35358`

```c
// src/tls13.c:14083
14080: * returns BAD_FUNC_ARG when ssl is NULL or not using TLS v1.3, SIDE_ERROR when
14081: * called on a client; WOLFSSL_SUCCESS on success and otherwise failure.
14082: */
14083:int wolfSSL_send_hrr_cookie(WOLFSSL* ssl, const unsigned char* secret,
14084:                            unsigned int secretSz)
14085:{
14086:    int ret;

// src/tls13.c:6620
6617:    int    ret;
6618:    byte   sessIdSz;
6619:
6620:    ret = TlsCheckCookie(ssl, cookie->data, cookie->len);
6621:    if (ret < 0)
6622:        return ret;
6623:    cookieDataSz = (word16)ret;

// src/tls13.c:6547
6544:#endif /* NO_SHA */
6545:
6546:    if (cookieSz < ssl->specs.hash_size + macSz)
6547:        return HRR_COOKIE_ERROR;
6548:    cookieSz -= macSz;
6549:
6550:    ret = wc_HmacInit(&cookieHmac, ssl->heap, ssl->devId);
```

The snippets above show the concrete implementation branch used for this decision. The full line list remains in the comparison JSON for reproducibility.

## Implementation Behavior
wolfSSL 支持单个 DTLS 1.3 HRR cookie secret 并允许应用重新设置或随机生成 secret；但没有内建双 secret 过渡窗口，也没有 cookie 时间戳/有效期策略。

## Inconsistency Reason
The implemented portion is visible in the cited source lines. The missing or unproven portion is: 当前实现支持应用设置/轮换单个 secret 和完整性验证，不提供内建过渡窗口或时间戳过期策略。

## Runtime Evidence
Focused source assertion tests were run and saved in `source_assertion_tests.log`.

```text
source_assertions 验证单 secret HMAC cookie 路径；未发现双 secret 或 timestamp 字段。
```

Full handshake-level runtime testing was blocked because the current local CMake cache disables DTLS 1.3/CID and no linked wolfSSL runtime binary was available.

## Impact
The impact depends on the feature: peers using the covered base path interoperate, but deployments depending on the missing conditional policy may get weaker validation, configuration-dependent behavior, or lack of proof for edge cases.

## Fix Direction
Add explicit tests and, where needed, explicit implementation branches for the missing condition. Prefer protocol-level unit tests that construct the exact DTLS 1.3 message or record variant and assert the expected alert, discard, or state transition.
