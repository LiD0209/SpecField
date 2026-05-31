# DTLS 1.3 legacy_session_id Handling Is Implemented, but Pre-DTLS 1.3 Cached-ID Reuse Is Rejected

## Summary

This report covers ID 114.

The original finding said wolfSSL lacks a pre-DTLS 1.3 cached session ID strategy. After re-checking the current source, this finding is only **partially true** and should be narrowed:

- wolfSSL can write a cached `sessionID` into the DTLS 1.3 ClientHello `legacy_session_id` field when a session object contains one.
- wolfSSL disables TLS 1.3 middlebox compatibility mode for DTLS 1.3, so a non-empty `legacy_session_id` is not generated merely as a TLS middlebox compatibility random value.
- wolfSSL's DTLS 1.3 server accepts a ClientHello with a non-empty `legacy_session_id`, but deliberately does not echo it in ServerHello.
- wolfSSL has a runtime-style unit test for this behavior: `test_dtls13_no_session_id_echo`.
- For a real pre-DTLS 1.3 / DTLS 1.2 session reused into a DTLS 1.3-minimum client, wolfSSL rejects `wolfSSL_set_session` rather than sending that pre-DTLS 1.3 cached session ID in a DTLS 1.3 ClientHello.

Therefore, ID 114 is best classified as **partially satisfied / policy mismatch**, not as a complete missing implementation.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 5.3, `ClientHello Format`.

Relevant original English text from RFC 9147:

```text
opaque legacy_session_id<0..32>;
```

```text
legacy_session_id:  Versions of TLS and DTLS before version 1.3 supported a "session resumption" feature, which has been merged with pre-shared keys (PSK) in version 1.3.
```

```text
A client which has a cached session ID set by a pre-DTLS 1.3 server SHOULD set this field to that value.
```

```text
Otherwise, it MUST be set as a zero-length vector (i.e., a zero-valued single byte length field).
```

The key word for the pre-DTLS 1.3 cached session ID behavior is `SHOULD`, not `MUST`. A library can choose a different compatibility policy, but that policy should be understood and tested.

## Relevant Source Code

### Client Writes a Cached Session ID When Present

`D:\project\wolfssl-master\src\tls13.c:4528`

```c
static void GetTls13SessionId(WOLFSSL* ssl, byte* output, word32* idx)
```

`D:\project\wolfssl-master\src\tls13.c:4529`

```c
if (ssl->session->sessionIDSz > 0) {
```

`D:\project\wolfssl-master\src\tls13.c:4533`

```c
output[*idx] = ssl->session->sessionIDSz;
```

`D:\project\wolfssl-master\src\tls13.c:4536`

```c
XMEMCPY(output + *idx, ssl->session->sessionID,
    ssl->session->sessionIDSz);
```

If `ssl->session->sessionIDSz` is non-zero and within `ID_LEN`, wolfSSL writes that cached ID into the TLS 1.3 / DTLS 1.3 ClientHello session-id vector.

### Otherwise the Client Writes Zero Length

`D:\project\wolfssl-master\src\tls13.c:4561`

```c
/* TLS v1.3 does not use session id - 0 length. */
if (output != NULL)
    output[*idx] = 0;
(*idx)++;
```

This matches RFC 9147's "otherwise zero-length vector" behavior.

### DTLS 1.3 Disables TLS Middlebox Compatibility Session ID

`D:\project\wolfssl-master\src\tls13.c:4718`

```c
if (ssl->options.dtls) {
    /* RFC 9147 Section 5: DTLS implementations do not use the
     *                     TLS 1.3 "compatibility mode" */
    ssl->options.tls13MiddleBoxCompat = 0;
}
```

This matters because TLS 1.3 middlebox compatibility mode can otherwise generate a 32-byte synthetic session ID. DTLS 1.3 disables that path, so a non-empty DTLS 1.3 `legacy_session_id` comes from a session object, not from middlebox compatibility.

### DTLS 1.3 ClientHello Uses This Helper

`D:\project\wolfssl-master\src\tls13.c:4938`

```c
GetTls13SessionId(ssl, args->output, &args->idx);
```

The DTLS 1.3 ClientHello generation path calls the same helper after writing the random.

### Different-Version Session Reuse Is Rejected

`D:\project\wolfssl-master\src\tls13.c:4643`

```c
if (ssl->options.resuming &&
        ssl->session->version.major != 0 &&
        (ssl->session->version.major != ssl->version.major ||
         ssl->session->version.minor != ssl->version.minor)) {
```

`D:\project\wolfssl-master\src\tls13.c:4650`

```c
/* Cannot resume with a different protocol version. */
ssl->options.resuming = 0;
ssl->version.major = ssl->session->version.major;
ssl->version.minor = ssl->session->version.minor;
return SendClientHello(ssl);
```

This is the policy difference for the RFC 9147 `SHOULD`: wolfSSL does not use a pre-DTLS 1.3 cached session as a DTLS 1.3 ClientHello compatibility value in the tested cross-version case. It rejects or downgrades the resumption path instead.

### Server Does Not Echo DTLS 1.3 legacy_session_id

`D:\project\wolfssl-master\src\tls13.c:7457`

```c
/* RFC 9147 Section 5.3: DTLS 1.3 ServerHello must have empty
 * legacy_session_id_echo. Don't store the client's value so it
 * won't be echoed in SendTls13ServerHello. */
if (ssl->options.dtls) {
    ssl->session->sessionIDSz = 0;
}
```

`D:\project\wolfssl-master\src\tls13.c:8063`

```c
/* RFC 9147 Section 5.3: DTLS 1.3 ServerHello must have empty
 * legacy_session_id_echo. */
output[idx++] = 0;
```

The server parses and bounds-checks the ClientHello session-id length, then deliberately avoids storing it for DTLS 1.3 so it cannot be echoed.

### Stateless HRR Path Also Clears the Session ID

`D:\project\wolfssl-master\src\dtls.c:864`

```c
/* RFC 9147 Section 5.3: DTLS 1.3 ServerHello must have empty
 * legacy_session_id_echo. Don't copy the client's session ID. */
nonConstSSL->session->sessionIDSz = 0;
```

This protects the HelloRetryRequest/stateless cookie path as well.

## Existing wolfSSL Test Coverage

### Non-Empty legacy_session_id Is Not Echoed

`D:\project\wolfssl-master\tests\api\test_dtls.c:2954`

```c
int test_dtls13_no_session_id_echo(void)
```

This test performs a first DTLS 1.3 handshake, obtains a session, forces `sess->sessionIDSz = ID_LEN` if needed, sets that session on a second DTLS 1.3 client, and verifies the ServerHello legacy session-id echo length byte is zero.

Important snippets:

```c
sess->sessionIDSz = ID_LEN;
```

```c
ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_SUCCESS);
```

```c
/* Client sends ClientHello (with non-empty legacy_session_id) */
```

```c
ExpectIntEQ(test_ctx.c_buff[DTLS_RECORD_HEADER_SZ +
    DTLS_HANDSHAKE_HEADER_SZ + OPAQUE16_LEN + RAN_LEN], 0);
```

This is direct evidence that wolfSSL's current DTLS 1.3 path handles a non-empty client `legacy_session_id` and does not echo it.

### Pre-DTLS 1.3 / DTLS 1.2 Session Is Rejected for DTLS 1.3 Minimum

`D:\project\wolfssl-master\tests\api\test_dtls.c:3136`

```c
int test_dtls_set_session_min_downgrade(void)
```

The test first obtains a DTLS 1.2 session, then creates a client with minimum version DTLS 1.3 and attempts to set that DTLS 1.2 session:

```c
ExpectIntEQ(wolfSSL_SetMinVersion(ssl_c, WOLFSSL_DTLSV1_3),
            WOLFSSL_SUCCESS);
ExpectIntEQ(wolfSSL_set_session(ssl_c, sess), WOLFSSL_FAILURE);
```

This test is important for ID 114 because it shows wolfSSL has an explicit cross-version session policy. It does not use the pre-DTLS 1.3 cached session ID in a DTLS 1.3 ClientHello; it rejects the session setup.

## Runtime Evidence

Compiled source-behavior harness:

`D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_legacy_session_id_114_source_check.c`

Build command:

```powershell
& 'D:\LLVM\bin\clang.exe' 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_legacy_session_id_114_source_check.c' -o 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_legacy_session_id_114_source_check.exe'
```

Run command:

```powershell
& 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_legacy_session_id_114_source_check.exe' *> 'D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_legacy_session_id_114_source_check.log'
```

Observed result:

```text
Conclusion: PASS - source behavior shows ID 114 is partially satisfied/partly superseded: wolfSSL can send a cached legacy_session_id in DTLS 1.3 and tests that the server does not echo it, but pre-DTLS-1.3 cross-version session reuse is rejected rather than used as a dedicated cached-ID compatibility strategy.
```

Selected assertions:

```text
PASS cached session ID is written when present                          contains "output[*idx] = ssl->session->sessionIDSz;"
PASS cached session ID bytes are copied                                 contains "XMEMCPY(output + *idx, ssl->session->sessionID"
PASS DTLS 1.3 disables TLS 1.3 middlebox compatibility mode             contains "ssl->options.tls13MiddleBoxCompat = 0;"
PASS DTLS 1.3 ClientHello calls GetTls13SessionId                       contains "GetTls13SessionId(ssl, args->output, &args->idx);"
PASS DTLS 1.3 server does not store client session ID                   contains "ssl->session->sessionIDSz = 0;"
PASS DTLS 1.3 ServerHello writes empty legacy_session_id_echo           contains "output[idx++] = 0;"
PASS wolfSSL test covers non-empty legacy_session_id no echo            contains "test_dtls13_no_session_id_echo"
PASS test covers DTLS 1.2 session rejected for DTLS 1.3 min             contains "wolfSSL_set_session(ssl_c, sess), WOLFSSL_FAILURE"
```

This is a compiled and executed source-behavior check. It is paired with wolfSSL's own DTLS API tests in `tests/api/test_dtls.c`.

## Inconsistency Reason

The original issue is not fully accurate for the current tree.

Implemented behavior:

| RFC 9147 area | wolfSSL behavior |
|---|---|
| ClientHello supports `legacy_session_id<0..32>` | Implemented through `GetTls13SessionId`. |
| Zero-length vector when no cached session ID exists | Implemented. |
| DTLS 1.3 avoids TLS middlebox compatibility session ID | Implemented by clearing `tls13MiddleBoxCompat`. |
| ServerHello legacy_session_id_echo is empty for DTLS 1.3 | Implemented and tested. |
| Non-empty client `legacy_session_id` does not break DTLS 1.3 server path | Tested by `test_dtls13_no_session_id_echo`. |

Remaining policy mismatch:

| RFC 9147 `SHOULD` behavior | wolfSSL behavior |
|---|---|
| A client with a cached session ID set by a pre-DTLS 1.3 server SHOULD set ClientHello `legacy_session_id` to that value. | A generic cached session ID can be written, but a DTLS 1.2 session reused into a DTLS 1.3-minimum client is rejected by `wolfSSL_set_session` in the existing test. |

Because RFC 9147 uses `SHOULD`, this is a partial compliance/policy finding rather than a hard protocol failure.

## Impact

The practical interoperability impact is limited. wolfSSL can process DTLS 1.3 ClientHello messages with non-empty `legacy_session_id` and correctly sends an empty ServerHello echo. However, applications expecting a pre-DTLS 1.3 cached session ID to be carried forward into a DTLS 1.3 ClientHello as an RFC 9147 compatibility hint will not get that behavior through the tested `wolfSSL_set_session` path.

## Suggested Fix Direction

If wolfSSL wants to implement the RFC 9147 `SHOULD` literally, add an explicit compatibility path that distinguishes:

1. Using a pre-DTLS 1.3 cached session ID as a DTLS 1.3 `legacy_session_id` value.
2. Actually resuming or downgrading with that old session.

The first can be allowed as a ClientHello compatibility field without treating the old session as a valid DTLS 1.3 resumption session. Add a dedicated test that obtains a DTLS 1.2 session ID, configures a DTLS 1.3 ClientHello to carry only that legacy ID, and verifies the server does not echo it.
