# OpenSSL ID045 RFC-8446 Compliance Check

## Summary
- Conclusion: In the tested OpenSSL TLS 1.3 code path, `unknown_identity` and `invalid_binder` lead to observably different outcomes in PSK-only mode. Therefore, the current behavior does not meet the RFC 8446 Appendix E.6 security expectation that these cases should be treated identically when the server only supports PSK handshakes.
- Scope: This issue affects the handling of the TLS 1.3 `pre_shared_key` extension and was validated in the `mixed` and `pskonly` runtime scenarios under `o001-100/id045_runtime`.

## RFC Exact Text
**Source:** `D:\project\conditionFuzzingPaper\document\TLS1.3.txt`

### 1) Binder validation and abort requirement
```text
3170    Prior to accepting PSK key establishment, the server MUST validate
3171    the corresponding binder value (see Section 4.2.11.2 below).  If this
3172    value is not present or does not validate, the server MUST abort the
3173    handshake.  Servers SHOULD NOT attempt to validate multiple binders;
3174    rather, they SHOULD select a single PSK and validate solely the
3175    binder that corresponds to that PSK.  See Section 8.2 and
3176    Appendix E.6 for the security rationale for this requirement.  In
3177    order to accept PSK key establishment, the server sends a
3178    "pre_shared_key" extension indicating the selected identity.
```

### 2) `unknown_psk_identity` vs `decrypt_error`
```text
5009    unknown_psk_identity:  Sent by servers when PSK key establishment is
5010       desired but no acceptable PSK identity is provided by the client.
5011       Sending this alert is OPTIONAL; servers MAY instead choose to send
5012       a "decrypt_error" alert to merely indicate an invalid PSK
5013       identity.
```

### 3) Appendix E.6 (PSK Identity Exposure)
```text
8465    Because implementations respond to an invalid PSK binder by aborting
8466    the handshake, it may be possible for an attacker to verify whether a
8467    given PSK identity is valid.  Specifically, if a server accepts both
8468    external-PSK handshakes and certificate-based handshakes, a valid PSK
8469    identity will result in a failed handshake, whereas an invalid
8470    identity will just be skipped and result in a successful certificate
8471    handshake.  Servers which solely support PSK handshakes may be able
8472    to resist this form of attack by treating the cases where there is no
8473    valid PSK identity and where there is an identity but it has an
8474    invalid binder identically.
```

## Code Exact Text (verbatim)

### A) No usable identity path can continue without binder-failure alert
**Source:** `openssl-master/ssl/statem/extensions_srvr.c`

```c
1462             if (ret == SSL_TICKET_NONE || ret == SSL_TICKET_NO_DECRYPT)
1463                 continue;

1521     if (sess == NULL)
1522         return 1;

1545     if (tls_psk_do_binder(s, md, PACKET_msg_start(pkt), binderoffset,
1546             PACKET_data(&binder), NULL, sess, 0, ext)
1547         != 1) {
```

### B) Invalid binder is a direct `decrypt_error` fatal path
**Source:** `openssl-master/ssl/statem/extensions.c`

```c
1968         ret = (CRYPTO_memcmp(binderin, binderout, hashsize) == 0);
1969         if (!ret)
1970             SSLfatal(s, SSL_AD_DECRYPT_ERROR, SSL_R_BINDER_DOES_NOT_VERIFY);
```

### C) Runtime observed divergence in PSK-only mode
**Source:** `o001-100/id045_runtime/result_pskonly_unknown_identity.txt`

```text
10 79:    Level=fatal(2), description=handshake failure(40)
```

**Source:** `o001-100/id045_runtime/result_pskonly_invalid_binder.txt`

```text
10 79:    Level=fatal(2), description=decrypt error(51)
12 64:40774080F6770000:error:0A0000FD:SSL routines:tls_psk_do_binder:binder does not verify:ssl/statem/extensions.c:1970:
```

## Why This Is Non-Compliant
RFC 8446 Appendix E.6 explains that, for servers operating in PSK-only mode, two cases should be handled in an indistinguishable way to reduce PSK identity exposure:

- no valid PSK identity is found
- a PSK identity is found, but its binder is invalid

However, OpenSSL exposes different observable behavior for these two cases.

### Observed behavior in OpenSSL
- When no usable PSK/session is selected, the server can leave the binder-failure path and continue extension processing (`sess == NULL -> return 1`), rather than immediately failing due to binder verification.
- When a PSK identity is selected but binder verification fails, OpenSSL immediately raises a fatal `decrypt_error(51)`.
- In the PSK-only runtime results, these two inputs are externally distinguishable:
- `unknown_identity` -> `handshake_failure(40)`
- `invalid_binder` -> `decrypt_error(51)`

### Compliance conclusion
As a result, the implementation does not provide identical observable treatment for:

- absence of a valid PSK identity
- presence of a PSK identity with an invalid binder

This is inconsistent with the security expectation described in RFC 8446 Appendix E.6 for PSK-only deployments.

## Security Impact
- Risk type: observable behavior side channel / PSK identity probing / authentication oracle

### Trigger conditions
- The TLS 1.3 PSK code path is reachable.
- An attacker can send crafted handshake messages with controlled PSK identities and binder values.
- The target server is configured for PSK-capable operation, especially PSK-only mode.

### Impact
- The server's different error behavior can allow an attacker to distinguish nonexistent PSK identities from existing identities with incorrect binders.
- This difference can be used as an oracle to test whether a candidate PSK identity is valid on the server.
- Once identity validity can be inferred, an attacker gains a stronger basis for targeted online guessing, identity enumeration, and follow-up attacks against deployments that rely on PSK secrecy for access control.
- In environments where PSK identities are sensitive or encode device, tenant, or service information, this behavior may leak operationally meaningful metadata and weaken the intended resistance against identity exposure described in RFC 8446 Appendix E.6.
