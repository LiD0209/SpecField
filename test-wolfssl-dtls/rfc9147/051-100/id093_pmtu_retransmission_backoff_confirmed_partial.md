# DTLS 1.3 PMTU-Unknown Retransmissions Do Not Back Off to Smaller Records

## Summary

RFC 9147 recommends that, when repeated DTLS handshake retransmissions do not produce a response and the PMTU is unknown, later retransmissions should back off to smaller record sizes and fragment the handshake message as needed.

wolfSSL supports DTLS MTU configuration, initial DTLS 1.3 handshake fragmentation, and DTLS 1.3 retransmission of buffered handshake records. However, the audited retransmission path resends the stored record data using the stored record length. It does not show a repeated-failure counter or a PMTU-unknown branch that reduces the target record size and re-fragments queued handshake messages.

This confirms ID 093 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Section 4.4, `PMTU Issues`, says DTLS records must fit within datagrams and applications should size records using PMTU information:

```text
DTLS records MUST NOT span datagrams.
```

The same section defines the relevant handshake retransmission guidance:

```text
If repeated retransmissions do not result in a response, and the
PMTU is unknown, subsequent retransmissions SHOULD back off to a
smaller record size, fragmenting the handshake message as
appropriate.
```

It also notes that the specification does not mandate an exact threshold:

```text
This specification does not specify an exact number of retransmits to
attempt before backing off, but 2-3 seems appropriate.
```

This is a `SHOULD`, not a `MUST`, so the result is partial rather than a hard protocol failure. The missing behavior is still relevant for interoperability on paths where large retransmitted handshake records are black-holed and no PMTU estimate is available.

## Code Behavior

### MTU and Initial Fragmentation Support Exist

wolfSSL exposes DTLS MTU state and setters. In `wolfssl-master/wolfssl/internal.h`, the connection state includes:

```c
word16          dtlsMtuSz;
```

In `wolfssl-master/src/ssl.c`, the API lets callers set an MTU:

```c
int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, word16 newMtu)
{
    ...
    ssl->dtlsMtuSz = newMtu;
    return WOLFSSL_SUCCESS;
}
```

For DTLS 1.3 handshake sends, `wolfssl-master/src/dtls13.c` computes the current maximum plaintext size and fragments if needed:

```c
maxFrag = wolfssl_local_GetMaxPlaintextSize(ssl);
maxLen = length;

if (maxLen < maxFrag) {
    ret = Dtls13SendOneFragmentRtx(ssl, handshakeType, outputSize, message,
        length, hashOutput);
}
else {
    ret = Dtls13SendFragmented(ssl, message, length, handshakeType,
        hashOutput);
}
```

The fragmented-send path recalculates fragment length from the current maximum plaintext size:

```c
maxFragment = wolfssl_local_GetMaxPlaintextSize(ssl);
...
fragLength = maxFragment - DTLS_HANDSHAKE_HEADER_SZ;
```

This satisfies the initial fragmentation part: wolfSSL can size initial handshake fragments according to the current MTU-related limits.

### Retransmission Buffers Store Concrete Records

In `wolfssl-master/wolfssl/internal.h`, the retransmission record stores already-built record data and its length:

```c
typedef struct Dtls13RtxRecord {
    struct Dtls13RtxRecord *next;
    word16 length;
    byte *data;
    w64wrapper epoch;
    w64wrapper seq[DTLS13_RETRANS_RN_SIZE];
    byte rnIdx;
    byte handshakeType;
} Dtls13RtxRecord;
```

The retransmission state has a field that might look like a retry counter, but it is explicitly marked unused:

```c
byte triggeredRtxs; /* Unused? */
```

The audited source does not use `triggeredRtxs` to count repeated failed retransmissions or to trigger PMTU backoff.

### Timeout Retransmission Resends the Buffered Records

In `wolfssl-master/src/dtls13.c`, `Dtls13RtxTimeout` handles timeout work and then retransmits buffered messages:

```c
/* Increase timeout on long timeout */
if (DtlsMsgPoolTimeout(ssl) != 0)
    return WOLFSSL_FATAL_ERROR;

return Dtls13RtxSendBuffered(ssl);
```

There is no visible branch in this timeout function that checks whether the PMTU is unknown, counts repeated no-response retransmissions, lowers `dtlsMtuSz`, lowers a retransmission fragment target, or re-fragments a queued handshake message.

### Buffered Retransmission Reuses the Stored Length

`Dtls13RtxSendBuffered` walks the retransmission list. It computes the send size from the stored record length:

```c
sendSz = r->length + headerLength;
```

It then copies the stored record body as-is:

```c
XMEMCPY(output + headerLength, r->data, r->length);
```

Finally it sends that same buffered handshake fragment:

```c
ret = Dtls13SendFragment(ssl, output, (word16)sendSz, r->length + headerLength,
    (enum HandShakeType)r->handshakeType, 0,
    isLast || !ssl->options.groupMessages);
```

This is normal retransmission behavior, but it does not implement the RFC 9147 PMTU-unknown fallback. If the original buffered record size is too large for the path and the PMTU remains unknown, the retransmission path keeps using the buffered length instead of shrinking and re-fragmenting.

### Tests Cover MTU and Fragmentation, Not PMTU-Unknown Backoff

The local wolfSSL tests include DTLS MTU and fragmentation coverage:

| Test location | Covered behavior |
|---|---|
| `wolfssl-master/tests/api/test_dtls.c`, `test_wolfSSL_dtls_set_mtu` | DTLS MTU setter accepts and rejects expected values |
| `wolfssl-master/tests/api/test_dtls.c`, `test_dtls_mtu_fragment_headroom` | DTLS records fit within a configured MTU after normal send sizing |
| `wolfssl-master/tests/api/test_dtls.c`, `test_dtls_mtu_split_messages` | DTLS message splitting under configured MTU |
| `wolfssl-master/tests/api/test_dtls.c`, DTLS retransmission interval test | Retransmission timing behavior |

I did not find a test that simulates unknown PMTU plus repeated no-response retransmissions and verifies that later retransmissions use smaller records.

## Runtime Evidence

### Compiled C Harness

I added a focused C harness:

```text
test-wolfssl-dtls/rfc9147/051-100/repro_pmtu_backoff_093_source_check.c
```

Build command run from the repository root:

```text
clang test-wolfssl-dtls/rfc9147/051-100/repro_pmtu_backoff_093_source_check.c -o test-wolfssl-dtls/rfc9147/051-100/repro_pmtu_backoff_093_source_check.exe
```

The executable was run and its output was saved here:

```text
test-wolfssl-dtls/rfc9147/051-100/repro_pmtu_backoff_093_source_check.log
```

Observed output:

```text
PASS initial DTLS 1.3 handshake fragmentation uses max plaintext size
PASS fragmented send path recalculates fragment length from current MTU sizing
PASS retransmission timeout resends buffered records
PASS buffered retransmission reuses stored record length
PASS retransmission timeout has no PMTU backoff or size-shrink branch
PASS buffered retransmission has no re-fragment-to-smaller-record branch
PASS normal MTU controls exist outside retransmission backoff path
PASS retransmission counter is not used for PMTU backoff
RESULT confirmed: wolfSSL fragments initial DTLS 1.3 sends, but repeated retransmission does not back off to smaller records when PMTU is unknown
```

This is a compiled source-behavior harness. It verifies the structural conditions for the finding: initial fragmentation exists, timeout retransmission exists, but the retransmission path lacks a PMTU-unknown smaller-record fallback. I did not rerun a full wolfSSL unit-test binary in this turn because no reusable `unit.test.exe` or `wolfssl.lib` was present under `wolfssl-master`, and the existing CMake cache under this test directory has `CMAKE_MAKE_PROGRAM-NOTFOUND`.

## Inconsistency

| Requirement component | wolfSSL behavior | Result |
|---|---|---|
| DTLS records must fit in datagrams | Normal MTU sizing and fragmentation paths exist | Satisfied |
| Handshake messages may be fragmented | `Dtls13HandshakeSend` and `Dtls13SendFragmentedInternal` implement fragmentation | Satisfied |
| Repeated PMTU-unknown retransmissions should back off to smaller records | `Dtls13RtxTimeout` calls `Dtls13RtxSendBuffered`; buffered retransmission reuses `r->length` and `r->data` | Missing |
| Backoff threshold such as 2-3 failed retransmits | `triggeredRtxs` exists but is marked unused and is not used in `dtls13.c` | Missing |

The result is therefore partial: the implementation has the basic DTLS 1.3 fragmentation and retransmission mechanisms, but the PMTU-unknown adaptive retransmission behavior described by RFC 9147 Section 4.4 is not visible in the audited path.

## Root Cause

The initial send path and retransmission path operate on different representations:

```text
initial send:
    full handshake message -> compute current max plaintext -> fragment
```

```text
retransmission:
    stored Dtls13RtxRecord { data, length } -> resend same stored fragment
```

Because retransmission stores concrete fragments rather than a re-fragmentable original handshake message plus a backoff policy, repeated timeouts have no place to choose a smaller record size.

## Impact

On networks where PMTU discovery is unavailable and a large handshake record is repeatedly dropped, retransmission may keep sending the same too-large record. That can delay or prevent handshake completion where an implementation that follows the RFC 9147 guidance would eventually retry using smaller fragments.

This is a compliance and robustness issue, not a direct memory safety issue.

## Suggested Fix

Track repeated retransmission failures when PMTU is unknown. After a small threshold such as 2-3 retransmissions, lower the retransmission record-size target and re-fragment the queued handshake message before sending again.

A robust fix likely needs the retransmission queue to retain enough information to re-fragment the original handshake message, rather than only resending already-built `Dtls13RtxRecord` fragments.
