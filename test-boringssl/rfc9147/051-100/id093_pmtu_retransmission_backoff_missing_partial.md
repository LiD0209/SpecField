# DTLS handshake retransmission does not back off to smaller records when PMTU is unknown

## Summary
BoringSSL fragments handshake messages to fit the current MTU, but repeated retransmission only doubles the timer and resends the same flight. I did not find logic that backs off to a smaller record size when PMTU is unknown after repeated non-response.

## Standard Requirement
- Official standard: https://www.rfc-editor.org/rfc/rfc9147#section-4.4
- Section: RFC 9147 Section 4.4, PMTU Issues

```text
If repeated retransmissions do not result in a response, and the PMTU is unknown, subsequent retransmissions SHOULD back off to a smaller record size, fragmenting the handshake message as appropriate.
```
该要求的核心是将 DTLS 1.3 的协议状态与线上的压缩字段区分开：wire header 可以只携带低位，但实现仍需要按标准语义处理完整状态、错误路径和 ACK/KeyUpdate 反馈。

## Relevant Source Code
ssl/d1_both.cc:875

```c++
875: static int send_flight(SSL *ssl) {
876:   if (ssl->s3->write_shutdown != ssl_shutdown_none) {
877:     OPENSSL_PUT_ERROR(SSL, SSL_R_PROTOCOL_IS_SHUTDOWN);
878:     return -1;
879:   }
880: 
881:   if (ssl->wbio == nullptr) {
882:     OPENSSL_PUT_ERROR(SSL, SSL_R_BIO_NOT_SET);
883:     return -1;
884:   }
885: 
886:   if (ssl->d1->num_timeouts > DTLS1_MAX_TIMEOUTS) {
887:     OPENSSL_PUT_ERROR(SSL, SSL_R_READ_TIMEOUT_EXPIRED);
888:     return -1;
889:   }
890: 
891:   dtls1_update_mtu(ssl);
892: 
893:   Array<uint8_t> packet;
894:   if (!packet.InitForOverwrite(ssl->d1->mtu)) {
895:     return -1;
896:   }
897: 
898:   while (ssl->d1->outgoing_written < ssl->d1->outgoing_messages.size()) {
899:     uint8_t old_written = ssl->d1->outgoing_written;
900:     uint32_t old_offset = ssl->d1->outgoing_offset;
901: 
902:     size_t packet_len;
903:     if (!seal_next_packet(ssl, Span(packet), &packet_len)) {
904:       return -1;
905:     }
906: 
907:     if (packet_len == 0 &&
908:         ssl->d1->outgoing_written < ssl->d1->outgoing_messages.size()) {
909:       // We made no progress with the packet size available, but did not reach
910:       // the end.
911:       OPENSSL_PUT_ERROR(SSL, SSL_R_MTU_TOO_SMALL);
912:       return false;
913:     }
```

ssl/d1_both.cc:1031

```c++
1031:   // Send the pending flight, if any.
1032:   if (ssl->d1->sending_flight) {
1033:     int ret = send_flight(ssl);
1034:     if (ret <= 0) {
1035:       return ret;
1036:     }
1037: 
1038:     // Reset state for the next send.
1039:     ssl->d1->outgoing_written = 0;
1040:     ssl->d1->outgoing_offset = 0;
1041:     ssl->d1->sending_flight = false;
1042: 
1043:     // Schedule the next retransmit timer. In DTLS 1.3, we retransmit all
1044:     // flights until ACKed. In DTLS 1.2, the final Finished flight is never
1045:     // ACKed, so we do not keep the timer running after the handshake.
1046:     if (SSL_in_init(ssl) || ssl_protocol_version(ssl) >= TLS1_3_VERSION) {
1047:       if (ssl->d1->num_timeouts == 0) {
1048:         ssl->d1->timeout_duration_ms = ssl->initial_timeout_duration_ms;
1049:       } else {
1050:         ssl->d1->timeout_duration_ms =
1051:             std::min(ssl->d1->timeout_duration_ms * 2, uint32_t{60000});
1052:       }
1053: 
1054:       OPENSSL_timeval now = ssl_ctx_get_current_time(ssl->ctx.get());
1055:       ssl->d1->retransmit_timer.StartMicroseconds(
```

## Implementation Behavior
复核代码证据 ssl/d1_both.cc:747, ssl/d1_both.cc:781, ssl/d1_both.cc:875, ssl/d1_both.cc:1031, ssl/d1_both.cc:1043。该路径显示：BoringSSL fragments handshake messages to fit the current MTU, but repeated retransmission only doubles the timer and resends the same flight. I did not find logic that backs off to a smaller record size when PMTU is unknown after repeated non-response.

## Inconsistency Reason
BoringSSL fragments handshake messages to fit the current MTU, but repeated retransmission only doubles the timer and resends the same flight. I did not find logic that backs off to a smaller record size when PMTU is unknown after repeated non-response.

## Runtime Evidence
Focused source-level checks were executed with `python focused_static_checks.py` and passed. Native BoringSSL runtime execution was blocked because this machine has no `cmake`, `ninja`, `go`, or prebuilt `ssl_test.exe`; see `runtime_blocker.log`.

## Impact
The impact is interoperability and robustness risk in DTLS 1.3 edge cases: long-lived rekeying, ACK/epoch reconstruction, server-side cookie retry behavior, or lossy-path PMTU recovery can diverge from RFC 9147 expectations.

## Fix Direction
Align the implementation state machine with the RFC requirement, then add BoringSSL runner coverage for the confirmed edge case. Where BoringSSL intentionally does not support the broader RFC feature, document the limit and fail in the protocol-appropriate way.
