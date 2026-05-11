# Epoch wrap guard uses a 16-bit ceiling

## Summary
The implementation prevents wrap but its guard is prev == 0xffff, not an implementation of the RFC 9147 64-bit epoch non-wrapping model.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-4.2
- Section: RFC 9147 Section 4.2, Sequence Number and Epoch

```text
The epoch number is initially zero and is incremented each time keying material changes ... Implementations MUST NOT allow the epoch to wrap.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
ssl/dtls_method.cc:52

```c++
52:     case ssl_encryption_application:
53:       if (prev < ssl_encryption_application &&
54:           ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
55:         *out = static_cast<uint16_t>(level);
56:         return true;
57:       }
58: 
59:       if (prev == 0xffff) {
60:         OPENSSL_PUT_ERROR(SSL, SSL_R_TOO_MANY_KEY_UPDATES);
61:         return false;
62:       }
63:       *out = prev + 1;
64:       return true;
```

## Implementation Behavior
复核代码证据 ssl/dtls_record.cc:71, ssl/dtls_record.cc:80, ssl/dtls_record.cc:122, ssl/dtls_record.cc:176, ssl/dtls_record.cc:316, ssl/dtls_record.cc:366, ssl/dtls_record.cc:372, ssl/dtls_method.cc:43, ssl/dtls_method.cc:59。该路径显示：The implementation prevents wrap but its guard is prev == 0xffff, not an implementation of the RFC 9147 64-bit epoch non-wrapping model.

## Inconsistency Reason
The implementation prevents wrap but its guard is prev == 0xffff, not an implementation of the RFC 9147 64-bit epoch non-wrapping model.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
