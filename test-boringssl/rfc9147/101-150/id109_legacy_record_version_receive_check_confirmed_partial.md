# DTLS legacy_record_version is partly ignored but still checked

## Summary
实现已完成发送侧兼容值设置：未协商前使用 DTLS 1.0 兼容值，DTLS 1.3 后续记录冻结为 DTLS 1.2。接收侧对 DTLSPlaintext 仍有 major-byte 或精确版本检查。

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section: RFC 9147 Section 4, Record Layer

```text
legacy_record_version: This value MUST be set to {254, 253} for all records other than the initial ClientHello. It MUST be ignored for all purposes.
```

标准同时约束发送值并要求接收侧不要依赖 legacy_record_version 作协议判断。

## Relevant Source Code
`ssl/dtls_record.cc:59`

```c
static uint16_t dtls_record_version(const SSL *ssl) {
  if (ssl->s3->version == 0) {
    return DTLS1_VERSION;
  }
  return ssl_protocol_version(ssl) >= TLS1_3_VERSION ? DTLS1_2_VERSION
                                                     : ssl->s3->version;
}
```

`ssl/dtls_record.cc:245`

```c
if (epoch == 0) {
  version_ok = (out->version >> 8) == DTLS1_VERSION_MAJOR;
} else {
  version_ok = out->version == dtls_record_version(ssl);
}
if (!version_ok) {
  return false;
}
```

发送路径符合 DTLS 1.3 兼容值，但接收路径仍检查该字段。

## Implementation Behavior
实现已完成发送侧兼容值设置：未协商前使用 DTLS 1.0 兼容值，DTLS 1.3 后续记录冻结为 DTLS 1.2。接收侧对 DTLSPlaintext 仍有 major-byte 或精确版本检查。

## Inconsistency Reason
已实现部分是发送值符合标准；缺失或条件依赖部分是接收端没有完全忽略 legacy_record_version，而是将不匹配值作为丢弃条件。

## Runtime Evidence
Focused test source: `phase2_dtls13_static_runtime_checks.py`

Focused test log: `phase2_dtls13_static_runtime_checks.log`

The test confirms the static code predicates for this finding. Full BoringSSL runner execution was blocked because this workspace has no `cmake`, `ninja`, `go`, or `bazel` in PATH and no prebuilt `ssl_test.exe` or `bssl_shim.exe` was found.

## Impact
可能导致符合 DTLS 1.3 但 legacy_record_version 非预期的记录被丢弃；风险较低，因为大量实现仍依赖兼容值。

## Fix Direction
评估是否可在 DTLS 1.3 已协商后放宽 DTLSPlaintext legacy_record_version 检查，只保留必要的解复用和安全边界检查。
