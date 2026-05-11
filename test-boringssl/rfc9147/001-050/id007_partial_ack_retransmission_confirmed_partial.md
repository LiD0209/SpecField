# DTLS 1.3 Partial ACK Retransmission Is Deferred Until Timer

## Summary

BoringSSL correctly parses DTLS 1.3 ACK records and marks the acknowledged record ranges, but a partial ACK does not immediately schedule retransmission of the unacknowledged part of the flight. The implementation only retransmits the remaining ranges when an existing retransmit timer later fires.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147, Section 7.1, "ACK Processing":

```text
Upon receiving an ACK for a partial flight (as mentioned in Section 7.1), the implementation transitions to the SENDING state, where it retransmits the unacknowledged portion of the flight.
```

中文说明：标准要求 partial ACK 触发发送状态，并重传该 flight 中尚未被 ACK 覆盖的部分，而不是只等待普通超时路径。

## Relevant Source Code

`ssl/d1_pkt.cc:98`

```c
// Mark each message as ACKed.
if (sent_record->first_msg == sent_record->last_msg) {
  ssl->d1->outgoing_messages[sent_record->first_msg].acked.MarkRange(
      sent_record->first_msg_start, sent_record->last_msg_end);
}
```

该代码说明 BoringSSL 能把 ACKed record 映射为 outgoing message 的已确认范围。

`ssl/d1_pkt.cc:122`

```c
if (std::all_of(ssl->d1->outgoing_messages.begin(),
                ssl->d1->outgoing_messages.end(),
                [](const auto &msg) { return msg.IsFullyAcked(); })) {
  dtls1_stop_timer(ssl);
  dtls_clear_outgoing_messages(ssl);
  ...
} else {
  // We may still be able to drop unused write epochs.
  dtls_clear_unused_write_epochs(ssl);

  // TODO(crbug.com/383016430): Schedule a retransmit. The peer will have
  // waited before sending the ACK, so a partial ACK suggests packet loss.
}
```

完整 ACK 分支会停止 timer 并清理 flight；partial ACK 分支没有设置 `sending_flight`，也没有启动立即重传，只留下 TODO。

`ssl/d1_both.cc:756`

```c
// Iterate over every un-acked range in the message, if any.
Span<const uint8_t> body = body_cbs;
for (;;) {
  auto range = msg.acked.NextUnmarkedRange(ssl->d1->outgoing_offset);
```

该发送路径证明 BoringSSL 在实际重传时会跳过已 ACK 范围，只发送未确认范围。

## Implementation Behavior

实现行为是部分满足：

| 部分 | 状态 |
|---|---|
| ACK 记录解析和格式校验 | 已实现 |
| ACKed record 到 sent message range 的映射 | 已实现 |
| 重传时省略已确认范围 | 已实现 |
| 收到 partial ACK 后立即进入发送/调度重传 | 缺失 |

## Inconsistency Reason

RFC 9147 要求 partial ACK 直接触发 SENDING 并重传未确认部分。BoringSSL 的数据结构已经足以计算未确认范围，但 `dtls1_process_ack` 的 partial ACK 分支只调用 `dtls_clear_unused_write_epochs`，并明确以 TODO 记录应调度 retransmit。因此它依赖后续普通 retransmit timer，而不是在 partial ACK 事件上立即调度。

## Runtime Evidence

Focused static/runtime-path test:

```powershell
python test-boringssl/001-050/verify_dtls13_static_paths.py
```

Result: passed. The test checks that `partial_ack_no_immediate_retransmit` is present in `ssl/d1_pkt.cc` and that the retransmit sender uses unmarked ranges.

Attempted BoringSSL runner command:

```powershell
go test ./ssl/test/runner -run 'TestRunner/(DTLS13RecordHeader-CIDBit|DTLS-Retransmit-Server-ACKForwards-TLS13|KeyUpdate-ToClient-PacketLoss-DTLS)' -count=1
```

Result: blocked because `go` is not installed or not available in PATH. The blocker is saved in `runner_blocker.log`.

## Impact

If a peer sends a partial ACK after detecting packet loss, BoringSSL may wait until its retransmit timer fires before sending the unacknowledged fragments. This can add avoidable latency to DTLS 1.3 loss recovery and diverges from the RFC state-machine text.

## Fix Direction

In the partial ACK branch of `dtls1_process_ack`, schedule retransmission of the remaining unacknowledged ranges immediately. A minimal fix should set the DTLS sending state or retransmit timer consistently with the existing `send_flight`/`dtls1_flush` machinery, while preserving the current range bitmap behavior so retransmission only includes unACKed fragments.
