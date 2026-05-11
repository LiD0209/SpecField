# BoringSSL DTLS 1.3 001-050 部分满足/不满足分类

- 分类条目总数: 1

## incomplete retransmission scheduling

| ID | 状态 | 风险 | decision | 原因 |
|---:|---|---|---|---|
| 007 | 部分满足 | medium | confirmed_partial | The retransmitted bytes are filtered to unacknowledged ranges, so the content-selection portion is implemented. The immediate state transition/scheduling required by the standard is not implemented in the partial ACK branch. |

- standard_check: RFC 9147 Section 7 states that on an ACK for a partial flight, the implementation transitions to SENDING and retransmits the unacknowledged portion of the flight.
- code_check: ssl/d1_pkt.cc marks ACKed record ranges and preserves unACKed ranges, but the partial-ACK branch at lines 148-154 only clears unused write epochs and contains a TODO to schedule a retransmit; it does not set sending_flight or restart the retransmit timer immediately.
- test_check: verify_dtls13_static_paths.py passed and explicitly checked partial_ack_no_immediate_retransmit. Focused Go runner execution was attempted but blocked because the go command is not installed; runner_blocker.log records the exact blocker.
