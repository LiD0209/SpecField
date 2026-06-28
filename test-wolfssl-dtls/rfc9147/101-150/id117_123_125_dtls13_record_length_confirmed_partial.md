# DTLS 1.3 Record Length Handling Is Partially Proven

## Summary  [non-English text removed]

This report covers IDs 117, 123, and 125.

wolfSSL implements important DTLS 1.3 record-length behavior. The sender always sets the DTLS 1.3 unified-header L bit and writes the explicit 16-bit length. The receiver parses explicit and omitted length forms, applies the generic 2^14 record-size limit with protocol overhead, and wolfSSL has a unit test that mutates the DTLS 1.3 length field beyond the datagram and expects the record to be discarded.

The remaining gaps are narrower than the original table wording:

|  ID | Result              | Reason                                                                                                                                                                                                                                                                                       |
| --: | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 117 | Partially satisfied | wolfSSL has generic `MAX_RECORD_SIZE == 16384` handling, but no DTLS-over-TCP-specific branch or test was found.                                                                                                                                                                           |
| 123 | Partially satisfied | wolfSSL's sender always includes the length field, so it does not appear to generate a non-final omitted-length record. The parser treats omitted length as "rest of datagram", but there is no explicit receiver-side proof that an omitted-length record is only accepted when it is last. |
| 125 | Partially satisfied | wolfSSL checks that length-field bytes and the minimum ciphertext bytes are present, and a unit test covers an oversized explicit length. However,`Dtls13ParseUnifiedRecordLayer` itself does not contain a direct `idx + recordLength <= inputSize` check.                              |

## Standard Requirement

Official standard: [https://www.rfc-editor.org/rfc/rfc9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant sections: RFC 9147 Section 4.2.1, `DTLSCiphertext`; Section 4.3, `Processing Multiple Records from the Same Datagram`; Section 4.4, `PMTU Issues`; Appendix B.1.

Relevant original English text from RFC 9147:

```text
L:  The L bit (0x04) is set if the length is present.
```

```text
Length:  Identical to the length field in a TLS 1.3 record.
```

```text
The length field MAY be omitted by clearing the L bit, which means that the record consumes the entire rest of the datagram in the lower level transport.
```

```text
Omitting the length field MUST only be used for the last record in a datagram.
```

```text
The final record in a datagram can omit the length field.
```

```text
For DTLS over TCP or SCTP, which automatically fragment and reassemble datagrams, there is no PMTU limitation. However, the upper layer protocol MUST NOT write any record that exceeds the maximum record size of 2^14 bytes.
```

RFC 9147 Appendix B.1 also lists an implementation check:

```text
Do you verify that the explicit record length is contained within the datagram in which it is contained?
```

## Relevant Source Code

### Sender Always Includes the L Bit

`D:\project\wolfssl-master\src\dtls13.c:1248`

```c
int Dtls13RlAddCiphertextHeader(WOLFSSL* ssl, byte* out, word16 length)
```

`D:\project\wolfssl-master\src\dtls13.c:1274`

```c
/* include 16-bit length */
*flags |= DTLS13_LEN_BIT;
```

`D:\project\wolfssl-master\src\dtls13.c:1279`

```c
c16toa(length, out + idx);
```

This means wolfSSL's normal DTLS 1.3 ciphertext sender does not omit the length field. For ID 123, that is an important implemented behavior: wolfSSL does not appear to generate a middle record with L bit cleared.

### Receiver Parses Explicit and Omitted Length Forms

`D:\project\wolfssl-master\src\dtls13.c:1523`

```c
int Dtls13ParseUnifiedRecordLayer(WOLFSSL* ssl, const byte* input,
    word16 inputSize, Dtls13UnifiedHdrInfo* hdrInfo)
```

`D:\project\wolfssl-master\src\dtls13.c:1544`

```c
hasLength = flags & DTLS13_LEN_BIT;
```

`D:\project\wolfssl-master\src\dtls13.c:1553`

```c
if (hasLength) {
    if (inputSize < idx + DTLS13_LEN_SIZE)
        return BUFFER_ERROR;

    ato16(input + idx, &hdrInfo->recordLength);
    idx += DTLS13_LEN_SIZE;
}
else {
    /* length not present. The size of the record is the all the remaining
       data received with this datagram */
    hdrInfo->recordLength = inputSize - idx;
}
```

For omitted length, wolfSSL follows the RFC interpretation that the record consumes the rest of the datagram. This makes the omitted-length form semantically last-record-only, but there is no explicit receiver-side error branch that says "reject omitted length unless this is the last record." Instead, the parser simply consumes the remainder.

### Explicit Length Has Partial Bounds Checking

`D:\project\wolfssl-master\src\dtls13.c:1570`

```c
if (hdrInfo->recordLength < DTLS13_RN_MASK_SIZE)
    return LENGTH_ERROR;
if (inputSize < idx + DTLS13_RN_MASK_SIZE)
    return BUFFER_ERROR;
```

These checks ensure enough ciphertext is present to deprotect the encrypted record number, but they are not equivalent to:

```c
idx + hdrInfo->recordLength <= inputSize
```

The direct full-record datagram-bounds check was not found inside `Dtls13ParseUnifiedRecordLayer`.

### Higher Layer Handles Partial UDP Reads

`D:\project\wolfssl-master\src\internal.c:12103`

```c
static int RecordsCanSpanReads(WOLFSSL *ssl)
```

`D:\project\wolfssl-master\src\internal.c:12170`

```c
if (readSize < ssl->dtls13CurRlLength + DTLS13_RN_MASK_SIZE) {
    if (!RecordsCanSpanReads(ssl)) {
        WOLFSSL_MSG("Partial record received");
        return DTLS_PARTIAL_RECORD_READ;
    }
```

This protects normal UDP-style DTLS from spanning datagrams. It is a higher-layer protection path, not a direct explicit-length bound in the unified-header parser.

### Generic 2^14 Record Limit Exists

`D:\project\wolfssl-master\wolfssl\internal.h:2315`

```c
#define MAX_RECORD_SIZE 16384  /* 2^14, max size by standard */
```

`D:\project\wolfssl-master\wolfssl\internal.h:1541`

```c
MAX_PLAINTEXT_SZ   = (1 << 14),        /* Max plaintext sz   */
```

`D:\project\wolfssl-master\src\internal.c:12461`

```c
/* record layer length check */
```

`D:\project\wolfssl-master\src\internal.c:12470`

```c
if (*size > (MAX_RECORD_SIZE + MAX_MSG_EXTRA +
        (ssl->options.usingCompression ? MAX_COMP_EXTRA : 0))) {
    WOLFSSL_MSG_EX("Record length %d exceeds max record size", *size);
    WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
    return LENGTH_ERROR;
}
```

The generic record limit exists. However, this audit did not find a DTLS-over-TCP-specific mode symbol or branch such as `DTLS_OVER_TCP`, nor a test that specifically exercises RFC 9147's DTLS-over-TCP 2^14 write limit.

## Existing wolfSSL Test Coverage

`D:\project\wolfssl-master\tests\api\test_dtls.c:1172`

```c
int test_dtls13_longer_length(void)
```

The test completes a DTLS 1.3 handshake, writes a valid client record, mutates the record length byte to make the record longer than the datagram, then expects the server read to fail without breaking subsequent communication:

```c
/* modify length to be bigger */
test_ctx.s_buff[0x2 + seq16bit] = 0xff;
```

```c
ExpectIntEQ(wolfSSL_read(ssl_s, readBuf, sizeof(readBuf)), -1);
ExpectIntEQ(wolfSSL_get_error(ssl_s, -1), WOLFSSL_ERROR_WANT_READ);
ExpectIntEQ(test_ctx.s_len, 0);
```

This is meaningful runtime-style coverage for ID 125. It confirms wolfSSL has a behavior path for oversized explicit length. The remaining concern is about where the check is implemented and whether the parser has a direct datagram-bounds condition.

## Runtime Evidence

Compiled source-behavior harness:

`D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_length_117_123_125_source_check.c`

Build command:

```powershell
& 'D:\LLVM\bin\clang.exe' 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_length_117_123_125_source_check.c' -o 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_length_117_123_125_source_check.exe'
```

Run command:

```powershell
& 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_length_117_123_125_source_check.exe' *> 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_length_117_123_125_source_check.log'
```

Observed result:

```text
Conclusion: PASS - source behavior confirms partial findings: wolfSSL always sends DTLS 1.3 records with L bit set and has generic 2^14 record sizing plus tests for oversized explicit length, but the parser lacks a direct idx+recordLength<=inputSize check and no DTLS-over-TCP-specific 2^14 branch was found.
```

Selected assertions:

```text
PASS sender includes DTLS 1.3 length bit                            contains "*flags |= DTLS13_LEN_BIT;"
PASS parser treats omitted length as datagram remainder             contains "hdrInfo->recordLength = inputSize - idx;"
PASS parser has no direct full-record bound check                   does not contain "idx + hdrInfo->recordLength"
PASS higher layer rejects partial UDP record                        contains "DTLS_PARTIAL_RECORD_READ"
PASS wolfSSL test mutates length larger than datagram               contains "test_dtls13_longer_length"
PASS 2^14 maximum record constant exists                            contains "#define MAX_RECORD_SIZE 16384"
PASS no explicit DTLS-over-TCP mode symbol                          does not contain "DTLS_OVER_TCP"
```

This is a compiled and executed source-behavior check. It is not a full packet-level DTLS-over-TCP interoperability test because no DTLS-over-TCP mode/test harness was found in the audited wolfSSL checkout.

## Inconsistency Reason

### ID 117

The original finding says "missing DTLS-over-TCP 2^14 limit." The audited source does contain the generic 2^14 maximum record constant and receive-side maximum record checks. It also sizes output through `wolfssl_local_GetMaxPlaintextSize`.

The partial gap is narrower: this audit did not find an explicit DTLS-over-TCP transport mode or a dedicated test proving that the upper layer cannot write a DTLS-over-TCP record over 2^14 bytes. The generic limit likely covers ordinary TLS/DTLS sizing, but the DTLS-over-TCP-specific requirement was not directly proven.

### ID 123

The sender path always sets `DTLS13_LEN_BIT`, so wolfSSL does not appear to emit omitted-length ciphertext records at all. Therefore, it also does not appear to emit an invalid non-final omitted-length record.

On the receive side, omitted length is parsed as "rest of datagram." This aligns with the standard's meaning, but there is no explicit validation branch that independently proves "L bit cleared only when this is the last record." The implementation relies on remainder consumption semantics.

### ID 125

wolfSSL checks that the explicit length field itself is present and that at least the minimum ciphertext bytes needed for record-number deprotection are present. A wolfSSL unit test also covers a length value larger than the datagram.

However, the parser does not contain a direct full-record bounds check of the form `idx + recordLength <= inputSize`. The protection appears to be distributed between the parser, higher-layer read behavior, and later record consumption.

## Impact

For normal wolfSSL-generated DTLS 1.3 traffic, the risk is low because outgoing records include the explicit length. For malformed inbound records, wolfSSL has defensive behavior and test coverage for oversized explicit length, but the lack of a direct parser-level full-record bounds check makes the compliance evidence less direct and easier to regress.

For DTLS-over-TCP, this audit could not prove dedicated enforcement because the relevant transport mode was not found.

## Suggested Fix Direction

1. Add an explicit parser check after reading `hdrInfo->recordLength`:

```c
if (inputSize < idx + hdrInfo->recordLength)
    return BUFFER_ERROR;
```

2. Add a targeted unit test for a DTLS 1.3 datagram containing multiple records where a non-final record clears the L bit.
3. Add or document a DTLS-over-TCP write-limit test that proves records above 2^14 bytes are rejected before transmission.
