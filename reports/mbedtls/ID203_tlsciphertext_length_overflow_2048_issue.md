# ID 203: Protected Record Length Uses a `+2048` Policy Instead of the TLS 1.3 `+256` Limit

- ID: `203`
- Status: `Unsatisfied`
- Category: `Record-layer length constraint difference`
- Variable: `TLSCiphertext.length`
- Change action: `invalid if value check fails`
- Change condition: `when a protected record exceeds the TLS 1.3 ciphertext length bound`

## 1. Specification Description (Original English)

### 1.1 Relevant TLS 1.3 requirement

Source: `document/TLS1.3.txt:4502`

```text
length:  The length (in bytes) of the following
   TLSCiphertext.encrypted_record, which is the sum of the lengths of
   the content and the padding, plus one for the inner content type,
   plus any expansion added by the AEAD algorithm.  The length
   MUST NOT exceed 2^14 + 256 bytes.  An endpoint that receives a
   record that exceeds this length MUST terminate the connection with
   a "record_overflow" alert.
```

Source: `document/TLS1.3.txt:4914`

```text
record_overflow:  A TLSCiphertext record was received that had a
   length more than 2^14 + 256 bytes, or a record decrypted to a
   TLSPlaintext record with more than 2^14 bytes (or some other
   negotiated limit).
```

The key point for ID `203` is:

- for TLS 1.3 protected records, `TLSCiphertext.length` must not exceed `2^14 + 256`
- if such a record is received, the endpoint must abort with `record_overflow`

This is a `MUST` requirement.

## 2. Code Description (Original Code / Direct Evidence)

### 2.1 mbedTLS uses a generic protected-payload overhead model

Source: `mbedtls-development/library/ssl_misc.h:244`

```c
/*
 * Allow extra bytes for record, authentication and encryption overhead:
 * counter (8) + header (5) + IV(16) + MAC (16-48) + padding (0-256).
 */
```

This comment shows that the implementation is built around a generic internal
record-overhead model rather than a TLS 1.3-specific ciphertext-length rule.

### 2.2 The configured protected-record payload bound is `content + 2048`

Source: `mbedtls-development/library/ssl_misc.h:309`

```c
#define MBEDTLS_SSL_PAYLOAD_OVERHEAD (MBEDTLS_MAX_IV_LENGTH +          \
                                      MBEDTLS_SSL_MAC_ADD +            \
                                      MBEDTLS_SSL_PADDING_ADD +        \
                                      MBEDTLS_SSL_MAX_CID_EXPANSION    \
                                      )

#define MBEDTLS_SSL_IN_PAYLOAD_LEN (MBEDTLS_SSL_PAYLOAD_OVERHEAD + \
                                    (MBEDTLS_SSL_IN_CONTENT_LEN))
```

Source: `mbedtls-development/library/ssl_misc.h:369`

```c
#if MBEDTLS_SSL_IN_PAYLOAD_LEN > MBEDTLS_SSL_IN_CONTENT_LEN + 2048
#error "Bad configuration - incoming protected record payload too large."
#endif
```

The direct implication is:

- the internal incoming protected-record allowance is bounded by `content + 2048`
- this is wider than the TLS 1.3 RFC bound of `2^14 + 256`

### 2.3 Runtime parsing reads the record length, but no TLS 1.3-specific `2^14 + 256` check is visible here

Source: `mbedtls-development/library/ssl_msg.c:3704`

```c
rec->data_len    = MBEDTLS_GET_UINT16_BE(buf, rec_hdr_len_offset);
```

Source: `mbedtls-development/library/ssl_msg.c:3714`

```c
if (rec->data_len == 0) {
    MBEDTLS_SSL_DEBUG_MSG(1, ("rejecting empty record"));
    return MBEDTLS_ERR_SSL_INVALID_RECORD;
}
```

The record header parser reads the ciphertext length and rejects the zero-length
case, but the inspected path does not show a dedicated TLS 1.3 check of the form:

- if `TLSCiphertext.length > 2^14 + 256`
- then abort with `record_overflow`

### 2.4 The later length check is against configured plaintext content length

Source: `mbedtls-development/library/ssl_msg.c:4011`

```c
if (rec->data_len > MBEDTLS_SSL_IN_CONTENT_LEN) {
    MBEDTLS_SSL_DEBUG_MSG(1, ("bad message length"));
    return MBEDTLS_ERR_SSL_INVALID_RECORD;
}
```

This check is useful, but it is not the same as the RFC rule above:

- it applies after preparation/deprotection to the actual record content length
- it returns `MBEDTLS_ERR_SSL_INVALID_RECORD`
- it is not a dedicated `record_overflow` handling path for oversized protected TLS 1.3 ciphertext records

## 3. Inconsistency

The inconsistency is about the protected-record upper bound itself.

TLS 1.3 requires:

- a fixed ciphertext bound of `2^14 + 256`

mbedTLS, as inspected here, is organized around:

- a generic internal payload allowance of `content + 2048`

This means the implementation model is not aligned with the RFC's precise TLS 1.3
ciphertext-length bound.

In addition, no dedicated receive-side branch was found here that clearly says:

- oversized TLS 1.3 protected record
- therefore send `record_overflow`

## 4. Why This Is Classified as `Unsatisfied`

This issue is stronger than a soft recommendation gap because the RFC wording is mandatory.

The standard does not merely suggest a conservative limit.
It requires a specific limit and a specific outcome:

- limit: `2^14 + 256`
- alert: `record_overflow`

mbedTLS does not appear to model this as a TLS 1.3-specific fixed bound.
Instead, it uses a broader internal protected-payload allowance and later generic
invalid-record checks.

So this is not just "different implementation style".
It is a mismatch in the enforced bound and in the protocol-specific error model.

## 5. Why `2048` Appears in the Code

The inspected code contains a general explanation for overhead accounting, but not a
direct rationale for choosing `2048` over the TLS 1.3 RFC limit of `256`.

What the code does show:

- it uses a library-wide overhead model covering IV, MAC, padding, and related additions
- the `+2048` value appears as part of a generic protected-payload configuration guard

What the code does not clearly state:

- a TLS 1.3-specific justification for replacing the RFC's `+256` ciphertext limit with `+2048`

So the likely explanation is that this is a shared internal buffer-policy choice rather
than a TLS 1.3-specific conformance rule, but that remains an implementation inference,
not an explicit source-code statement.

## 6. Conclusion

For ID `203`, TLS 1.3 requires that protected records must not exceed `2^14 + 256`
bytes and that oversized records must trigger `record_overflow`.

mbedTLS instead uses a broader `content + 2048` protected-payload policy in its
internal configuration model, and the inspected runtime checks do not show a dedicated
TLS 1.3 `record_overflow` branch tied to the RFC's exact ciphertext limit.

Therefore, this is a genuine standards mismatch, and classifying ID `203` as
`Unsatisfied` is reasonable.
