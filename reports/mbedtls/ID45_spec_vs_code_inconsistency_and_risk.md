# PSK binder validation and identity exposure risk (mbedTLS vs RFC 8446)

## 1. Specification Description

### 1.1 PSK binder validation and handling requirements

From [RFC 8446 (TLS 1.3), Section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11):

```text
Prior to accepting PSK key establishment, the server MUST validate
the corresponding binder value (see Section 4.2.11.2 below).  If this
value is not present or does not validate, the server MUST abort the
handshake.  Servers SHOULD NOT attempt to validate multiple binders;
rather, they SHOULD select a single PSK and validate solely the
binder that corresponds to that PSK.  See Section 8.2 and
Appendix E.6 for the security rationale for this requirement.  In
order to accept PSK key establishment, the server sends a
"pre_shared_key" extension indicating the selected identity.
```

### 1.2 Relationship between `unknown_psk_identity` and `decrypt_error`

From [RFC 8446, Section 6.2](https://www.rfc-editor.org/rfc/rfc8446#section-6.2):

```text
unknown_psk_identity:  Sent by servers when PSK key establishment is
   desired but no acceptable PSK identity is provided by the client.
   Sending this alert is OPTIONAL; servers MAY instead choose to send
   a "decrypt_error" alert to merely indicate an invalid PSK
```

### 1.3 Appendix E.6 text (PSK Identity Exposure)

From [RFC 8446, Appendix E.6](https://www.rfc-editor.org/rfc/rfc8446#appendix-E.6):

```text
Because implementations respond to an invalid PSK binder by aborting
the handshake, it may be possible for an attacker to verify whether a
given PSK identity is valid.  Specifically, if a server accepts both
external-PSK handshakes and certificate-based handshakes, a valid PSK
identity will result in a failed handshake, whereas an invalid
identity will just be skipped and result in a successful certificate
handshake.  Servers which solely support PSK handshakes may be able
to resist this form of attack by treating the cases where there is no
valid PSK identity and where there is an identity but it has an
invalid binder identically.
```

## 2. Code Description

### 2.1 Code comment describing binder-failure behavior

From `library/ssl_tls13_server.c`:

```c
* anything to do with binder check. A binder check is done only when a
* suitable pre-shared-key has been selected and only for that selected
* pre-shared-key: if the binder check fails, we fail the handshake and we do
* not try to find another pre-shared-key for which the binder check would
* succeed as recommended by the specification.
```

### 2.2 `invalid binder` branch

From `library/ssl_tls13_server.c`:

```c
ret = ssl_tls13_offered_psks_check_binder_match(
    ssl, binder, binder_len, psk->type,
    mbedtls_md_psa_alg_from_type((mbedtls_md_type_t) psk->ciphersuite_info->mac));
if (ret != SSL_TLS1_3_BINDER_MATCH) {
    /* For security reasons, the handshake should be aborted when we
     * fail to validate a binder value. See RFC 8446 section 4.2.11.2
     * and appendix E.6. */
#if defined(MBEDTLS_SSL_SESSION_TICKETS)
    mbedtls_ssl_session_free(&session);
#endif
    MBEDTLS_SSL_DEBUG_MSG(3, ("Invalid binder."));
    MBEDTLS_SSL_DEBUG_RET(
        1, "ssl_tls13_offered_psks_check_binder_match", ret);
    MBEDTLS_SSL_PEND_FATAL_ALERT(
        MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR,
        MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
    return ret;
```

### 2.3 `no valid identity` branch

From `library/ssl_tls13_server.c`:

```c
if (matched_identity == -1) {
    MBEDTLS_SSL_DEBUG_MSG(3, ("No usable PSK or ticket."));
    return MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY;
```

### 2.4 Special handling of `UNKNOWN_IDENTITY` by caller

From `library/ssl_tls13_server.c`:

```c
if (ret == 0) {
    got_psk = 1;
} else if (ret != MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY) {
    MBEDTLS_SSL_DEBUG_RET(
        1, "ssl_tls13_parse_pre_shared_key_ext", ret);
    return ret;
```

### 2.5 Subsequent handshake mode selection

From `library/ssl_tls13_server.c`:

```c
if (ssl_tls13_key_exchange_is_ephemeral_available(ssl)) {
    handshake->key_exchange_mode =
        MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL;
    MBEDTLS_SSL_DEBUG_MSG(2, ("key exchange mode: ephemeral"));
...
else {
    MBEDTLS_SSL_DEBUG_MSG(
        1,
        ("ClientHello message misses mandatory extensions."));
    MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_MISSING_EXTENSION,
                                 MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
    return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
```

## 3. Points of Inconsistency

1. Appendix E.6 explicitly states:
   - "servers which solely support PSK handshakes ... treat ... invalid binder identically"
   - In the code, `invalid binder` and `matched_identity == -1` enter different return paths:
     - `invalid binder`: set pending `decrypt_error` and return error
     - `no valid identity`: return `MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY`

2. Caller behavior further amplifies path differences:
   - It returns immediately only when `ret != MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY`
   - `UNKNOWN_IDENTITY` allows proceeding to subsequent mode selection (e.g., `ephemeral` mode)

3. The "ability to verify whether an identity is valid" scenario described in Appendix E.6 is observable in this implementation:
   - `invalid binder` tends to fail immediately
   - `no valid identity` may be skipped and continue with certificate handshake (when certificate mode is supported)

## 4. Potential Risks

1. **PSK identity enumeration risk**
   - An attacker can construct two classes of inputs: "identity exists but binder is wrong" and "identity does not exist", and infer identity validity from handshake outcome, alerts, or timing differences.

2. **Authentication mode probing (oracle) risk**
   - On servers that support both PSK and certificate handshakes, `invalid binder` and `unknown identity` may trigger "failure" vs "fallback to certificate handshake", creating an exploitable behavioral side channel.

3. **Offline probing aid for account/device identifiers**
   - If PSK identity correlates with business identifiers (device ID / tenant ID / account), this difference can be used to efficiently filter for "existing identifier sets".

## 5. Conclusion

- The Appendix E.6 security recommendation in RFC 8446 is not implemented in an equivalent way by the current code path: the code does not fully process "no valid identity" and "identity present but binder invalid" as identical cases.
- This inconsistency has the conditions to form a security-observable surface and constitutes a substantive security risk.

## 6. WSL Actual Deployment Test (Dynamic Validation)

- Test environment: WSL2 Ubuntu 24.04
- Binaries: `build/mbedtls-wsl-id45/programs/ssl/ssl_server2`, `ssl_client2`
- Automation script: `m001-100/id45_wsl_runtime/run_id45_wsl_test.sh`
- Detailed results: `m001-100/id45_wsl_runtime/id45_wsl_runtime_interpretation.md`

Core dynamic test results:

1. Mixed mode (certificate + PSK)
   - `unknown identity`: client handshake succeeds (`client_rc=0`), server log contains `No usable PSK or ticket.`
   - `invalid binder`: client handshake fails (`client_rc=1`), server log contains `Invalid binder.` and sends fatal alert `message=51`
   - Interpretation: the two input classes are clearly distinguishable (success vs failure)

2. PSK-only mode
   - `unknown identity`: server sends fatal alert `message=109`
   - `invalid binder`: server sends fatal alert `message=51`
   - Interpretation: the two input classes remain distinguishable (different fatal alert codes)

Conclusion: static analysis and dynamic deployment tests are consistent; the inconsistency is observable at runtime.
