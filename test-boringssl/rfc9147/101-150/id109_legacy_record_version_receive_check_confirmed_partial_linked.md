# DTLSPlaintext legacy_record_version Is Still Checked on Receive

## Summary

RFC 9147 freezes the DTLS 1.3 `DTLSPlaintext.legacy_record_version` wire value for compatibility, but also says the field must be ignored for all purposes.

BoringSSL satisfies the sender-side compatibility value. For negotiated DTLS 1.3, outbound DTLSPlaintext records use DTLS 1.2 (`{254,253}`) as the legacy record version.

The receive side is only partially aligned. BoringSSL's DTLSPlaintext parser still reads and validates the record version field. For epoch 0, it accepts only the DTLS major version byte. For later DTLSPlaintext records, it requires an exact match with `dtls_record_version(ssl)`. This confirms RFC 9147 ID 109 as **partially satisfied**.

## Standard Requirement

RFC 9147, Section 4, "The DTLS Record Layer", defines the DTLSPlaintext header:

```text
struct {
    ContentType type;
    ProtocolVersion legacy_record_version;
    uint16 epoch = 0
    uint48 sequence_number;
    uint16 length;
    opaque fragment[DTLSPlaintext.length];
} DTLSPlaintext;
```

The field requirement is:

```text
legacy_record_version:  This value MUST be set to {254, 253} for all
   records other than the initial ClientHello (i.e., one not
   generated after a HelloRetryRequest), where it may also be {254,
   255} for compatibility purposes.  It MUST be ignored for all
   purposes.  See [TLS13], Appendix D.1 for the rationale for this.
```

This creates two distinct requirements:

| Direction | Requirement |
|---|---|
| Sending DTLS 1.3 DTLSPlaintext | Use the compatibility value `{254,253}`, except the initial ClientHello may also use `{254,255}` |
| Receiving DTLS 1.3 DTLSPlaintext | Ignore `legacy_record_version` for all purposes |

The first requirement is about wire compatibility. The second is about receiver behavior: the field must not be used as a protocol decision point.

## Code Behavior

### Sender Uses the DTLS 1.3 Compatibility Value

In `ssl/dtls_record.cc`, BoringSSL computes the outgoing record version with `dtls_record_version`:

```cpp
static uint16_t dtls_record_version(const SSL *ssl) {
  if (ssl->s3->version == 0) {
    // Before the version is determined, outgoing records use dTLS 1.0 for
    // historical compatibility requirements.
    return DTLS1_VERSION;
  }
  // DTLS 1.3 freezes the record version at DTLS 1.2. Previous ones use the
  // version itself.
  return ssl_protocol_version(ssl) >= TLS1_3_VERSION ? DTLS1_2_VERSION
                                                     : ssl->s3->version;
}
```

When writing a DTLS 1.2-style plaintext record header, BoringSSL stores that computed value:

```cpp
uint16_t record_version = dtls_record_version(ssl);
...
out[0] = type;
CRYPTO_store_u16_be(out + 1, record_version);
```

For negotiated DTLS 1.3, `dtls_record_version` returns `DTLS1_2_VERSION`, which corresponds to `{254,253}`. This satisfies the sender-side compatibility requirement.

### Receive Path Still Validates the Field

In `ssl/dtls_record.cc`, the inbound DTLSPlaintext parser reads the record version into `out->version`:

```cpp
if (!CBS_get_u16(in, &out->version) ||
    !CBS_get_u64(in, &epoch_and_seq) ||
    !CBS_get_u16_length_prefixed(in, &out->body)) {
  return false;
}
```

The parser then uses that field to decide whether to accept or drop the record:

```cpp
uint16_t epoch = out->number.epoch();
bool version_ok;
if (epoch == 0) {
  // Only check the first byte. Enforcing beyond that can prevent decoding
  // version negotiation failure alerts.
  version_ok = (out->version >> 8) == DTLS1_VERSION_MAJOR;
} else {
  version_ok = out->version == dtls_record_version(ssl);
}
if (!version_ok) {
  return false;
}
```

This is the partial mismatch. The implementation does not fully ignore `legacy_record_version`; it uses the field as a record acceptance condition.

### Scope of the Checked Path

This finding applies to DTLSPlaintext records that use the DTLS 1.2-style record header. It does not apply to encrypted DTLS 1.3 `DTLSCiphertext` unified headers, which do not contain `legacy_record_version`.

BoringSSL also has a DTLS 1.3 unified-header parser for encrypted records:

```cpp
static bool parse_dtls13_record(SSL *ssl, CBS *in, ParsedDTLSRecord *out)
```

That parser does not read a `legacy_record_version` field. The mismatch is specifically in the DTLSPlaintext parsing path that still uses the legacy DTLS record header format.

## Runner Coverage

The BoringSSL runner registers record-version tests from `ssl/test/runner/runner.go`:

```go
addRecordVersionTests()
```

The test definitions in `ssl/test/runner/version_tests.go` include a record-version enforcement test:

```go
// Test that the record version is enforced.
testCases = append(testCases, testCase{
    name: "CheckRecordVersion-" + ver.name,
    config: Config{
        MinVersion: ver.version,
        MaxVersion: ver.version,
        Bugs: ProtocolBugs{
            SendRecordVersion: 0x03ff,
        },
    },
    shouldFail:    true,
    expectedError: ":WRONG_VERSION_NUMBER:",
})
```

The runner also contains initial ClientHello record-version tests such as:

```text
LooseInitialRecordVersion-*
GarbageInitialRecordVersion-*
```

This coverage confirms that record-version enforcement is intentional in the current test suite. It does not cover the RFC 9147 receive-side rule that DTLS 1.3 `DTLSPlaintext.legacy_record_version` must be ignored for all purposes.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_legacy_record_version_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\101-150 -B D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe --config Release --target repro_dtls13_legacy_record_version_probe
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\build-linked-probe\Release\repro_dtls13_legacy_record_version_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\101-150\repro_dtls13_legacy_record_version_probe.log
```

Observed output:

```text
linked BoringSSL probe: PASS
send behavior: dtls_record_version freezes DTLS 1.3 outbound legacy_record_version at DTLS 1.2
receive behavior: parse_dtls12_record still reads and checks DTLSPlaintext legacy_record_version
receive detail: epoch 0 permits only DTLS major byte, later epochs require exact dtls_record_version
runner coverage: addRecordVersionTests registers CheckRecordVersion and initial-record-version tests
conclusion: RFC 9147 ID 109 is confirmed partially satisfied
```

The probe confirms linkage with BoringSSL through `DTLS_method()`, then checks the relevant product and runner source predicates for sender behavior, receive-side version filtering, and runner coverage.

## Inconsistency

| Requirement component | BoringSSL behavior |
|---|---|
| DTLS 1.3 sender must use `{254,253}` for non-initial DTLSPlaintext records | Implemented through `dtls_record_version` |
| Initial ClientHello may use `{254,255}` for compatibility | Pre-negotiation compatibility logic exists |
| Receiver must ignore `legacy_record_version` for all purposes | Receive path still validates the field |
| Epoch 0 DTLSPlaintext should not make protocol decisions from this field | Parser requires the DTLS major byte |
| Later DTLSPlaintext records should not make protocol decisions from this field | Parser requires exact `dtls_record_version(ssl)` |

The inconsistency is therefore directional. BoringSSL sends the RFC 9147 compatibility value correctly, but it still applies DTLS 1.2-era receive filtering to a field that RFC 9147 says must be ignored.

## Root Cause

The DTLSPlaintext receive parser reuses legacy DTLS record-version validation logic. That logic made sense for older DTLS versions, where the record version was treated as part of record-layer version checking.

In DTLS 1.3, the field remains in DTLSPlaintext for compatibility, but it is no longer supposed to control record acceptance. BoringSSL freezes the outbound value for DTLS 1.3, but the inbound parser still treats the field as meaningful.

## Impact

This is a protocol conformance and interoperability issue.

| Impact area | Description |
|---|---|
| Protocol compliance | The receive path does not fully implement RFC 9147's "MUST be ignored for all purposes" rule. |
| Interoperability | A peer sending an otherwise valid DTLS 1.3 DTLSPlaintext record with a non-standard legacy version value may be dropped. |
| Test behavior | Existing runner tests reinforce record-version enforcement rather than the DTLS 1.3 ignore rule. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as overly strict receive-side validation of a DTLS 1.3 compatibility field.

## Suggested Fix

For negotiated DTLS 1.3, BoringSSL should evaluate whether DTLSPlaintext receive processing can ignore `legacy_record_version` as RFC 9147 requires, while preserving necessary pre-negotiation and older-DTLS compatibility behavior.

Regression coverage should include:

| Test case | Expected result |
|---|---|
| DTLS 1.3 outbound DTLSPlaintext after negotiation | Uses `{254,253}` |
| DTLS 1.3 initial ClientHello compatibility value | Accepts permitted compatibility behavior |
| DTLS 1.3 receive-side DTLSPlaintext with non-standard `legacy_record_version` but otherwise valid record | Ignores the field |
| DTLS 1.2 record-version enforcement | Preserves existing DTLS 1.2 behavior where applicable |
