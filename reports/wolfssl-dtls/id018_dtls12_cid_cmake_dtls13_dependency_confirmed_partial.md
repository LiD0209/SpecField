# CMake DTLS CID Option Incorrectly Requires DTLS 1.3

## Summary
This finding is a CMake build-configuration mismatch, not a DTLS record-layer data-path violation.

wolfSSL does implement DTLS 1.2 Connection ID support: it defines the RFC 9146 `tls12_cid(25)` content type, exposes CID APIs, negotiates the `connection_id` extension, emits DTLS 1.2 CID records, validates received CIDs, and has a dedicated DTLS 1.2 CID test. However, the CMake option `WOLFSSL_DTLS_CID` rejects configurations unless `WOLFSSL_DTLS13` is also enabled. That prevents a CMake user from enabling DTLS 1.2 CID alone, even though RFC 9146 is specifically a DTLS 1.2 CID specification and the source tree contains a DTLS 1.2 implementation path.

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9146

RFC 9146 defines Connection Identifiers for DTLS 1.2. Section 10.3 registers the new TLS content type:

```text
Value: 25
Description: tls12_cid
DTLS-OK: Y
Reference: RFC 9146
Comment: The tls12_cid content type is only applicable to DTLS 1.2.
```

The important constraint is that `tls12_cid(25)` is a DTLS 1.2 content type. DTLS 1.3 CID uses a different record-header mechanism and should not rely on the DTLS 1.2 `tls12_cid` content type.

## Relevant Source Code
`CMakeLists.txt` requires DTLS 1.3 when enabling DTLS CID:

```cmake
CMakeLists.txt:423
if(WOLFSSL_DTLS_CID)
    if(NOT WOLFSSL_DTLS13)
        message(FATAL_ERROR "CID are supported only for DTLSv1.3")
    endif()
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_DTLS_CID")
endif()
```

The autotools configure path does not impose the same DTLS 1.3 dependency:

```m4
configure.ac:5723
AC_ARG_ENABLE([dtlscid],
    [AS_HELP_STRING([--enable-dtlscid],[Enable wolfSSL DTLS ConnectionID (default: disabled)])],
    [ ENABLED_DTLS_CID=$enableval ],
    [ ENABLED_DTLS_CID=no ]
    )
if test "x$ENABLED_DTLS_CID" = "xyes"
then
AM_CFLAGS="$AM_CFLAGS -DWOLFSSL_DTLS_CID"
fi
```

The DTLS 1.2 record-layer constant is present:

```c
wolfssl/internal.h:6614
enum ContentType {
    no_type            = 0,
    change_cipher_spec = 20,
    alert              = 21,
    handshake          = 22,
    application_data   = 23,
    dtls12_cid         = 25,
#ifdef WOLFSSL_DTLS13
    ack                = 26,
#endif
};
```

The DTLS 1.2 send path uses `dtls12_cid` when a transmit CID is configured:

```c
src/internal.c:24488
#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_DTLS_CID)
            if (ssl->options.dtls && DtlsGetCidTxSize(ssl) > 0)
                args->type = dtls12_cid;
#endif
```

The DTLS 1.2 receive path validates the received CID:

```c
src/internal.c:12205
#ifdef WOLFSSL_DTLS_CID
    if (rh->type == dtls12_cid) {
        byte* ourCid = NULL;
        if (ssl->buffers.inputBuffer.length - *inOutIdx <
                (word32)cidSz + LENGTH_SZ)
            return LENGTH_ERROR;
        if (wolfSSL_dtls_cid_get0_rx(ssl, &ourCid) != WOLFSSL_SUCCESS)
            return DTLS_CID_ERROR;
        if (XMEMCMP(ssl->buffers.inputBuffer.buffer + *inOutIdx, ourCid, cidSz)
                != 0)
            return DTLS_CID_ERROR;
        *inOutIdx += cidSz;
    }
#endif
```

There is a dedicated DTLS 1.2 CID test:

```c
tests/api/test_dtls.c:37
int test_dtls12_basic_connection_id(void)
{
#if defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES) && defined(WOLFSSL_DTLS_CID)
    ...
    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c,
        &ssl_s, wolfDTLSv1_2_client_method, wolfDTLSv1_2_server_method),
        0);

    ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_c), 1);
    ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_c, server_cid,
            sizeof(server_cid)), 1);
    ExpectIntEQ(wolfSSL_dtls_cid_use(ssl_s), 1);
    ExpectIntEQ(wolfSSL_dtls_cid_set(ssl_s, client_cid,
            sizeof(client_cid)), 1);
```

DTLS 1.3 CID uses a different unified-header CID bit path:

```c
src/dtls13.c:1163
static int Dtls13AddCID(WOLFSSL* ssl, byte* flags, byte* out, word16* idx)
{
    ...
    *flags |= DTLS13_CID_BIT;
    ...
}
```

## Implementation Behavior
The DTLS 1.2 CID implementation exists in the source tree and is not just a placeholder. The API path enables the `connection_id` extension, the send path changes the outer record type to `dtls12_cid`, the receive path checks the CID bytes, and the test suite includes a DTLS 1.2 handshake/data-flow test using `wolfDTLSv1_2_client_method` and `wolfDTLSv1_2_server_method`.

The problem is specifically the CMake enablement path: `WOLFSSL_DTLS_CID=yes` is rejected unless `WOLFSSL_DTLS13=yes`. This does not match the protocol feature's DTLS 1.2 applicability and is inconsistent with the autotools `--enable-dtlscid` path.

## Inconsistency Reason
RFC 9146 defines a DTLS 1.2 CID content type. wolfSSL's record-layer implementation supports that DTLS 1.2 content type, and DTLS 1.3 has a separate unified-header CID mechanism.

The inconsistent part is that the CMake configuration says CID is supported only for DTLS 1.3. That statement is too narrow and blocks a valid DTLS 1.2 CID-only build configuration.

This should be classified as `confirmed_partial` because:

- Implemented: DTLS 1.2 CID data-plane support exists.
- Implemented: DTLS 1.3 CID does not appear to misuse `tls12_cid(25)`.
- Missing/inconsistent: CMake cannot enable the DTLS 1.2 CID feature unless DTLS 1.3 is also enabled.

## Runtime Evidence
Focused verification script: `test-wolfssl-dtls/rfc9146/001-022/verify_wolfssl_dtls_cid_001_022.py`

Log file: `test-wolfssl-dtls/rfc9146/001-022/verify_wolfssl_dtls_cid_001_022.log`

The verification confirms:

- CMake rejects `WOLFSSL_DTLS_CID` without `WOLFSSL_DTLS13`.
- `dtls12_cid = 25` exists.
- The DTLS 1.2 sender sets `args->type = dtls12_cid`.
- The sender writes the CID and inner content type.
- The checked default build does not expose `WOLFSSL_DTLS_CID` because the option is disabled.

## Impact
CMake users cannot build a DTLS 1.2-only CID configuration through the documented CMake option, despite the source code containing DTLS 1.2 CID support. This can lead to unnecessary DTLS 1.3 enablement or to the false impression that wolfSSL has no DTLS 1.2 CID implementation.

## Fix Direction
Adjust the CMake option logic so that `WOLFSSL_DTLS_CID` requires DTLS support, not DTLS 1.3 specifically. For example, allow `WOLFSSL_DTLS_CID` when `WOLFSSL_DTLS` is enabled, and keep DTLS 1.3-specific CID checks inside DTLS 1.3-specific code paths.

If the maintainers intentionally only support the CMake CID option together with DTLS 1.3, the option text and fatal error should be renamed or clarified so it does not contradict the existing DTLS 1.2 CID implementation.
