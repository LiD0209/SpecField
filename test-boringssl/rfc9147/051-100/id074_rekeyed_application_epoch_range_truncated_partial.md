# Rekeyed application epoch range is truncated by 16-bit epoch state

## Summary
RFC 9147 reserves epochs 4 through 2^64-1 for rekeyed application traffic, with a sending safety limit of 2^48-1. BoringSSL's DTLS epoch state is uint16_t and next_epoch fails at 0xffff, so it covers only a prefix of the specified application epoch space.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-4.2
- Section: RFC 9147 Section 4.2, Sequence Number and Epoch

```text
The epoch number is initially zero and is incremented each time keying material changes ... Implementations MUST NOT allow the epoch to wrap.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
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

ssl/dtls_method.cc:111

```c++
111: static bool dtls1_set_write_state(SSL *ssl, ssl_encryption_level_t level,
112:                                   UniquePtr<SSLAEADContext> aead_ctx,
113:                                   Span<const uint8_t> traffic_secret) {
114:   uint16_t epoch;
115:   if (!next_epoch(ssl, &epoch, level, ssl->d1->write_epoch.epoch())) {
116:     return false;
117:   }
118: 
119:   DTLSWriteEpoch new_epoch;
120:   new_epoch.aead = std::move(aead_ctx);
121:   new_epoch.next_record = DTLSRecordNumber(epoch, 0);
122:   new_epoch.traffic_secret.CopyFrom(traffic_secret);
123:   if (ssl_protocol_version(ssl) > TLS1_2_VERSION) {
124:     new_epoch.rn_encrypter =
125:         RecordNumberEncrypter::Create(new_epoch.aead->cipher(), traffic_secret);
126:     if (new_epoch.rn_encrypter == nullptr) {
127:       return false;
128:     }
129:   }
130: 
131:   auto current = MakeUnique<DTLSWriteEpoch>(std::move(ssl->d1->write_epoch));
132:   if (current == nullptr) {
133:     return false;
134:   }
135: 
136:   ssl->d1->write_epoch = std::move(new_epoch);
137:   ssl->d1->extra_write_epochs.PushBack(std::move(current));
138:   dtls_clear_unused_write_epochs(ssl);
139:   return true;
```

## Implementation Behavior
复核代码证据 ssl/dtls_record.cc:71, ssl/dtls_record.cc:80, ssl/dtls_record.cc:122, ssl/dtls_record.cc:176, ssl/dtls_record.cc:316, ssl/dtls_record.cc:366, ssl/dtls_record.cc:372, ssl/dtls_method.cc:43, ssl/dtls_method.cc:59。该路径显示：RFC 9147 reserves epochs 4 through 2^64-1 for rekeyed application traffic, with a sending safety limit of 2^48-1. BoringSSL's DTLS epoch state is uint16_t and next_epoch fails at 0xffff, so it covers only a prefix of the specified application epoch space.

## Inconsistency Reason
RFC 9147 reserves epochs 4 through 2^64-1 for rekeyed application traffic, with a sending safety limit of 2^48-1. BoringSSL's DTLS epoch state is uint16_t and next_epoch fails at 0xffff, so it covers only a prefix of the specified application epoch space.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
