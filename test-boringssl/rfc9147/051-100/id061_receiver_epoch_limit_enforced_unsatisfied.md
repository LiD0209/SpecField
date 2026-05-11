# DTLS 1.3 receiver epoch space is limited to 16 bits

## Summary
RFC 9147 says receiving implementations MUST NOT enforce the sending-side epoch limit. BoringSSL reconstructs and tracks epochs in uint16_t and rejects ACK RecordNumber epochs above UINT16_MAX, so the receiver cannot represent or accept the RFC 9147 64-bit epoch space.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-4.2
- Section: RFC 9147 Section 4.2, Sequence Number and Epoch

```text
The epoch number is initially zero and is incremented each time keying material changes ... Implementations MUST NOT allow the epoch to wrap.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
ssl/dtls_record.cc:80

```c++
80: // reconstruct_epoch finds the largest epoch that ends with the epoch bits from
81: // |wire_epoch| that is less than or equal to |current_epoch|, to match the
82: // epoch reconstruction algorithm described in RFC 9147 section 4.2.2.
83: static uint16_t reconstruct_epoch(uint8_t wire_epoch, uint16_t current_epoch) {
84:   uint16_t current_epoch_high = current_epoch & 0xfffc;
85:   uint16_t epoch = (wire_epoch & 0x3) | current_epoch_high;
86:   if (epoch > current_epoch && current_epoch_high > 0) {
87:     epoch -= 0x4;
88:   }
89:   return epoch;
90: }
```

ssl/d1_pkt.cc:70

```c++
70:     // During the handshake, records must be ACKed at the same or higher epoch.
71:     // See https://www.rfc-editor.org/errata/eid8108. Additionally, if the
72:     // record does not fit in DTLSRecordNumber, it is definitely not a record
73:     // number that we sent.
74:     if ((ack_record_number.epoch() < ssl_encryption_application &&
75:          epoch > ack_record_number.epoch()) ||
76:         epoch > UINT16_MAX || seq > DTLSRecordNumber::kMaxSequence) {
77:       OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
78:       *out_alert = SSL_AD_ILLEGAL_PARAMETER;
79:       return ssl_open_record_error;
```

ssl/dtls_method.cc:43

```c++
43: static bool next_epoch(const SSL *ssl, uint16_t *out,
44:                        ssl_encryption_level_t level, uint16_t prev) {
45:   switch (level) {
46:     case ssl_encryption_initial:
47:     case ssl_encryption_early_data:
48:     case ssl_encryption_handshake:
49:       *out = static_cast<uint16_t>(level);
50:       return true;
51: 
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
复核代码证据 ssl/dtls_record.cc:71, ssl/dtls_record.cc:80, ssl/dtls_record.cc:122, ssl/dtls_record.cc:176, ssl/dtls_record.cc:316, ssl/dtls_record.cc:366, ssl/dtls_record.cc:372, ssl/dtls_method.cc:43, ssl/dtls_method.cc:59。该路径显示：RFC 9147 says receiving implementations MUST NOT enforce the sending-side epoch limit. BoringSSL reconstructs and tracks epochs in uint16_t and rejects ACK RecordNumber epochs above UINT16_MAX, so the receiver cannot represent or accept the RFC 9147 64-bit epoch space.

## Inconsistency Reason
RFC 9147 says receiving implementations MUST NOT enforce the sending-side epoch limit. BoringSSL reconstructs and tracks epochs in uint16_t and rejects ACK RecordNumber epochs above UINT16_MAX, so the receiver cannot represent or accept the RFC 9147 64-bit epoch space.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
