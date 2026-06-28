# mbedTLS TLS 1.3 `certificate_authorities` Validation Gap

## 1. Problem Summary

In the TLS 1.3 `CertificateRequest` parsing path, mbedTLS accepts the `certificate_authorities` extension type, but does not implement dedicated parsing of its internal structure. As a result, the client does not explicitly validate:

- whether the `authorities` vector satisfies `3..2^16-1`
- whether each `DistinguishedName` satisfies `1..2^16-1`

In practice, malformed `certificate_authorities` contents can be received and ignored, instead of being rejected during handshake parsing.

## 2. RFC 8446 Source Text

From [RFC 8446 (TLS 1.3), Section 4.2.4](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.4):

```text
4.2.4.  Certificate Authorities

   The "certificate_authorities" extension is used to indicate the
   certificate authorities (CAs) which an endpoint supports and which
   SHOULD be used by the receiving endpoint to guide certificate
   selection.

   The body of the "certificate_authorities" extension consists of a
   CertificateAuthoritiesExtension structure.

      opaque DistinguishedName<1..2^16-1>;

      struct {
          DistinguishedName authorities<3..2^16-1>;
      } CertificateAuthoritiesExtension;

   authorities:  A list of the distinguished names [X501] of acceptable
   certificate authorities, represented in DER-encoded [X690] format.
```

## 3. Code Description

### 3.1 `certificate_authorities` is allowed in `CertificateRequest`

From `library/ssl_misc.h`:

```c
/* RFC 8446 section 4.2. Allowed extensions for CertificateRequest */
#define MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CR                                  \
    (MBEDTLS_SSL_EXT_MASK(STATUS_REQUEST)                         | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG)                                | \
     MBEDTLS_SSL_EXT_MASK(SCT)                                    | \
     MBEDTLS_SSL_EXT_MASK(CERT_AUTH)                              | \
     MBEDTLS_SSL_EXT_MASK(OID_FILTERS)                            | \
     MBEDTLS_SSL_EXT_MASK(SIG_ALG_CERT)                           | \
     MBEDTLS_SSL_TLS1_3_EXT_MASK_UNRECOGNIZED)
```

This means mbedTLS recognizes `certificate_authorities` as a legal extension type in TLS 1.3 `CertificateRequest`.

### 3.2 Generic extension check only validates outer legality, not inner structure

From `library/ssl_tls13_generic.c`:

```c
int mbedtls_ssl_tls13_check_received_extension(
    mbedtls_ssl_context *ssl,
    int hs_msg_type,
    unsigned int received_extension_type,
    uint32_t hs_msg_allowed_extensions_mask)
{
    uint32_t extension_mask = mbedtls_ssl_get_extension_mask(
        received_extension_type);

    if ((extension_mask & hs_msg_allowed_extensions_mask) == 0) {
        ...
        return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
    }

    ssl->handshake->received_extensions |= extension_mask;
    ...
    return 0;
}
```

This function checks whether the extension type is legal in the current handshake message. It does **not** validate the internal format of `certificate_authorities`.

### 3.3 TLS 1.3 client parser ignores `certificate_authorities` payload

From `library/ssl_tls13_client.c`:

```c
while (p < extensions_end) {
    unsigned int extension_type;
    size_t extension_data_len;

    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, 4);
    extension_type = MBEDTLS_GET_UINT16_BE(p, 0);
    extension_data_len = MBEDTLS_GET_UINT16_BE(p, 2);
    p += 4;

    MBEDTLS_SSL_CHK_BUF_READ_PTR(p, extensions_end, extension_data_len);

    ret = mbedtls_ssl_tls13_check_received_extension(
        ssl, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST, extension_type,
        MBEDTLS_SSL_TLS1_3_ALLOWED_EXTS_OF_CR);
    if (ret != 0) {
        return ret;
    }

    switch (extension_type) {
        case MBEDTLS_TLS_EXT_SIG_ALG:
            ...
            break;

        default:
            MBEDTLS_SSL_PRINT_EXT(
                3, MBEDTLS_SSL_HS_CERTIFICATE_REQUEST,
                extension_type, "( ignored )");
            break;
    }

    p += extension_data_len;
}
```

- `signature_algorithms` has dedicated parsing.
- `certificate_authorities` falls into the `default` branch and its body is only skipped, not semantically validated.

## 4. Runtime Evidence

During runtime validation, a malformed `certificate_authorities` extension was injected into `CertificateRequest`. The client received and ignored it:

```text
ssl_tls13_generic.c:1608: |3| CertificateRequest: certificate_authorities(47) extension received.
ssl_tls13_client.c:2474: |3| CertificateRequest: certificate_authorities(47) extension ( ignored ).
ssl_tls13_client.c:2550: |2| <= parse certificate request
```

The handshake still completed successfully:

```text
HTTP/1.0 200 OK
Content-Type: text/html

<h2>Mbed TLS Test Server</h2>
<p>Successful connection using: TLS1-3-CHACHA20-POLY1305-SHA256</p>
```

This runtime result is consistent with the code path: malformed `certificate_authorities` contents are not rejected by a dedicated parser.

## 5. Why This Is Inconsistent

The inconsistency is not that mbedTLS fails to recognize the extension type — it does recognize it.

The real inconsistency is:

- RFC 8446 defines a concrete internal structure and concrete range constraints.
- mbedTLS only checks the outer extension container.
- mbedTLS does not enforce the inner structure constraints when the extension is present.

So the implementation is only a partial match to the RFC intent:

- compliant at the level of extension-type admission
- not fully compliant at the level of structure validation

## 6. Root Cause

1. `certificate_authorities` is included in the allowed extension mask.
2. The generic extension framework only checks whether the extension is legal in this message.
3. The TLS 1.3 `CertificateRequest` parser only gives special treatment to `signature_algorithms`.
4. No dedicated parser exists for `certificate_authorities`.

Because of that, malformed payloads are skipped rather than rejected.

## 7. Conclusion

The current mbedTLS behavior:

- `certificate_authorities` is recognized but not fully parsed in TLS 1.3 `CertificateRequest`
- RFC-defined inner length constraints are not explicitly enforced
- malformed contents can be accepted and ignored
