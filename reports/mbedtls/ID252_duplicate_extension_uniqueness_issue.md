# ID 252: Duplicate Extension-Type Uniqueness Is Not Enforced as a Unified Hard-Fail Rule

- ID: `252`
- Status: `Unsatisfied`
- Category: `Extension uniqueness validation gap`
- Variable: `extension_type`
- Change action: `must not repeat`
- Change condition: `within one extension block`

## 1. Specification Description (Original English)

### 1.1 Relevant TLS 1.3 requirement

Source: `document/TLS1.3.txt:2079-2084`

```text
When multiple extensions of different types are present, the
extensions MAY appear in any order, with the exception of
"pre_shared_key" (Section 4.2.11) which MUST be the last extension in
the ClientHello (but can appear anywhere in the ServerHello
extensions block).  There MUST NOT be more than one extension of the
same type in a given extension block.
```

For ID `252`, the key normative point is the last sentence:

- `MUST NOT` means this is a mandatory prohibition, not an optional recommendation;
- the scope is one extension block (for example, one `ClientHello.extensions` list);
- inside that block, each `extension_type` can appear at most once.

The same paragraph also clarifies the nearby ordering rule:

- different extension types may generally appear in any order (`MAY`);
- but `pre_shared_key` in `ClientHello` is a special case and `MUST` be last.

## 2. Code Description (Original Code / Direct Evidence)

### 2.1 Server parses extensions in a loop and checks legality, but no generic duplicate hard-fail branch is visible

Source: `mbedtls-development/library/ssl_tls13_server.c:1488`

```c
if (handshake->received_extensions & MBEDTLS_SSL_EXT_MASK(PRE_SHARED_KEY)) {
    ...
    return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
}
...
ret = mbedtls_ssl_tls13_check_received_extension(
    ssl, MBEDTLS_SSL_HS_CLIENT_HELLO, extension_type,
    allowed_exts);
```

What this clearly shows:

- there is a special rule for `pre_shared_key` placement (`must be last`);
- extension legality is checked through `mbedtls_ssl_tls13_check_received_extension()`.

But this is not a generic "duplicate extension type" hard-fail path for all extension types.

### 2.2 Generic checker updates a bitmask but does not reject already-seen extension types

Source: `mbedtls-development/library/ssl_tls13_generic.c:1599`

```c
int mbedtls_ssl_tls13_check_received_extension(...)
{
    ...
    if ((extension_mask & hs_msg_allowed_extensions_mask) == 0) {
        ...
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ssl->handshake->received_extensions |= extension_mask;
    ...
}
```

This function:

- rejects extensions that are not allowed in the current message;
- marks extensions as seen via a bitmask.

However, no branch of the form below is present in this generic check:

```c
if (already_seen(extension_type)) abort;
```

So the implementation model is not a unified duplicate-type hard rejection.

## 3. Empirical Behavior (Probe Test)

### 3.1 Test setup

Source: `mbedtls-development/tests/suites/test_suite_ssl.function:6704`

- The probe takes a valid TLS 1.3 `ClientHello`.
- It duplicates one extension entry (`supported_versions`, type `43`) inside the same extension block.
- Then it lets the handshake continue.

Key mutation logic:

Source: `mbedtls-development/tests/suites/test_suite_ssl.function:6811`

```c
if (MBEDTLS_GET_UINT16_BE(q, 0) == (uint16_t) extension_type && dup_ptr == NULL) {
    dup_ptr = q;
    dup_len = 4 + cur_len;
}
...
memcpy(mut + prefix_len, dup_ptr, dup_len);
```

### 3.2 Observed result

Source: `mbedtls-development/tests/suites/test_suite_ssl.data:3548`

```text
tls13_clienthello_duplicate_extension_probe:43:MBEDTLS_ERR_SSL_INVALID_MAC
```

The observed failure is `MBEDTLS_ERR_SSL_INVALID_MAC`, not an immediate duplicate-extension alert path.

## 4. Why It Can Still Be Rejected Even Without a Unified Duplicate Check

This point is important:

- The handshake can still fail later because the tampered on-wire `ClientHello` changes transcript bytes.
- Client and server then derive different handshake secrets.
- The mismatch surfaces at authentication/MAC verification, resulting in `INVALID_MAC`.

So "eventually rejected" does not prove "duplicate extension was explicitly rejected by rule".
It only proves the connection failed at a later cryptographic consistency stage.

## 5. Inconsistency

The inconsistency is:

- RFC 8446 requires a direct uniqueness rule (`MUST NOT` duplicate extension type in one block).
- mbedTLS does not show a unified, explicit duplicate-type hard-fail mechanism in the generic extension checker.
- In the probe, failure is observed, but as a late `INVALID_MAC` outcome rather than a direct duplicate-extension semantic rejection.

Therefore, the mismatch is real at the rule-enforcement model level.

## 6. Conclusion

For ID `252`, TLS 1.3 imposes a mandatory uniqueness constraint on extension types per extension block.

In the inspected mbedTLS paths:

- extension legality and some special rules are implemented;
- but no unified generic duplicate-extension hard-fail check is clearly present.

The duplicate-extension probe still fails, but with `MBEDTLS_ERR_SSL_INVALID_MAC`, which is consistent with late transcript/key mismatch rather than explicit duplicate-rule enforcement.

So classifying ID `252` as `Unsatisfied` remains reasonable.
