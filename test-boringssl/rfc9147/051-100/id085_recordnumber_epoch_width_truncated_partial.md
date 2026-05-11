# RecordNumber source model is narrower than RFC 9147

## Summary
RFC 9147 expands RecordNumber to uint64 epoch plus uint64 sequence_number for ACK and AEAD inputs. BoringSSL encodes ACK fields as u64, but the source values come from DTLSRecordNumber with a 16-bit epoch and 48-bit sequence.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-4.2
- Section: RFC 9147 Section 4.2, Sequence Number and Epoch

```text
The epoch number is initially zero and is incremented each time keying material changes ... Implementations MUST NOT allow the epoch to wrap.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
ssl/internal.h:635

```c++
635: // Record layer.
636: 
637: class DTLSRecordNumber {
638:  public:
639:   static constexpr uint64_t kMaxSequence = (uint64_t{1} << 48) - 1;
640: 
641:   DTLSRecordNumber() = default;
642:   DTLSRecordNumber(uint16_t epoch, uint64_t sequence) {
643:     BSSL_CHECK(sequence <= kMaxSequence);
644:     combined_ = (uint64_t{epoch} << 48) | sequence;
645:   }
646: 
647:   static DTLSRecordNumber FromCombined(uint64_t combined) {
648:     return DTLSRecordNumber(combined);
649:   }
650: 
651:   bool operator==(DTLSRecordNumber r) const {
652:     return combined() == r.combined();
653:   }
654:   bool operator!=(DTLSRecordNumber r) const { return !((*this) == r); }
655:   bool operator<(DTLSRecordNumber r) const { return combined() < r.combined(); }
656: 
657:   uint64_t combined() const { return combined_; }
658:   uint16_t epoch() const { return combined_ >> 48; }
659:   uint64_t sequence() const { return combined_ & kMaxSequence; }
660: 
661:   bool HasNext() const { return sequence() < kMaxSequence; }
662:   DTLSRecordNumber Next() const {
```

ssl/d1_both.cc:981

```c++
981:   for (size_t i = ssl->d1->records_to_ack.size() - num_acks;
982:        i < ssl->d1->records_to_ack.size(); i++) {
983:     sorted.PushBack(ssl->d1->records_to_ack[i]);
984:   }
985:   std::sort(sorted.begin(), sorted.end());
986: 
987:   uint8_t buf[2 + 16 * DTLS_MAX_ACK_BUFFER];
988:   CBB cbb, child;
989:   CBB_init_fixed(&cbb, buf, sizeof(buf));
990:   BSSL_CHECK(CBB_add_u16_length_prefixed(&cbb, &child));
991:   for (const auto &number : sorted) {
992:     BSSL_CHECK(CBB_add_u64(&child, number.epoch()));
993:     BSSL_CHECK(CBB_add_u64(&child, number.sequence()));
```

## Implementation Behavior
复核代码证据 ssl/dtls_record.cc:71, ssl/dtls_record.cc:80, ssl/dtls_record.cc:122, ssl/dtls_record.cc:176, ssl/dtls_record.cc:316, ssl/dtls_record.cc:366, ssl/dtls_record.cc:372, ssl/dtls_method.cc:43, ssl/dtls_method.cc:59。该路径显示：RFC 9147 expands RecordNumber to uint64 epoch plus uint64 sequence_number for ACK and AEAD inputs. BoringSSL encodes ACK fields as u64, but the source values come from DTLSRecordNumber with a 16-bit epoch and 48-bit sequence.

## Inconsistency Reason
RFC 9147 expands RecordNumber to uint64 epoch plus uint64 sequence_number for ACK and AEAD inputs. BoringSSL encodes ACK fields as u64, but the source values come from DTLSRecordNumber with a 16-bit epoch and 48-bit sequence.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
