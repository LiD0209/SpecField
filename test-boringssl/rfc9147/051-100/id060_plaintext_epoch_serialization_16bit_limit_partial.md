# DTLSPlaintext epoch serialization is implemented only over a 16-bit epoch model

## Summary
RFC 9147 describes the connection epoch as an 8-octet counter whose low two octets appear in DTLSPlaintext. BoringSSL serializes and stores DTLS epochs as uint16_t/DTLSRecordNumber epochs, so it implements the low-two-octet wire form but not the full 64-bit connection epoch model.

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

ssl/dtls_record.cc:525

```c++
525:   uint16_t record_version = dtls_record_version(ssl);
526:   if (dtls13_header) {
527:     // The first byte of the DTLS 1.3 record header has the following format:
528:     // 0 1 2 3 4 5 6 7
529:     // +-+-+-+-+-+-+-+-+
530:     // |0|0|1|C|S|L|E E|
531:     // +-+-+-+-+-+-+-+-+
532:     //
533:     // We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1 (length
534:     // is present), which is a mask of 0x2c. The E E bits are the low-order two
535:     // bits of the epoch.
536:     //
537:     // +-+-+-+-+-+-+-+-+
538:     // |0|0|1|0|1|1|E E|
539:     // +-+-+-+-+-+-+-+-+
540:     out[0] = 0x2c | (epoch & 0x3);
541:     // We always use a two-byte sequence number. A one-byte sequence number
542:     // would require coordinating with the application on ACK feedback to know
543:     // that the peer is not too far behind.
544:     CRYPTO_store_u16_be(out + 1, write_epoch->next_record.sequence());
545:     // TODO(crbug.com/383078467): When we know the record is last in the packet,
546:     // omit the length.
547:     CRYPTO_store_u16_be(out + 3, ciphertext_len);
548:   } else {
```

## Implementation Behavior
复核代码证据 ssl/dtls_record.cc:71, ssl/dtls_record.cc:80, ssl/dtls_record.cc:122, ssl/dtls_record.cc:176, ssl/dtls_record.cc:316, ssl/dtls_record.cc:366, ssl/dtls_record.cc:372, ssl/dtls_method.cc:43, ssl/dtls_method.cc:59。该路径显示：RFC 9147 describes the connection epoch as an 8-octet counter whose low two octets appear in DTLSPlaintext. BoringSSL serializes and stores DTLS epochs as uint16_t/DTLSRecordNumber epochs, so it implements the low-two-octet wire form but not the full 64-bit connection epoch model.

## Inconsistency Reason
RFC 9147 describes the connection epoch as an 8-octet counter whose low two octets appear in DTLSPlaintext. BoringSSL serializes and stores DTLS epochs as uint16_t/DTLSRecordNumber epochs, so it implements the low-two-octet wire form but not the full 64-bit connection epoch model.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
