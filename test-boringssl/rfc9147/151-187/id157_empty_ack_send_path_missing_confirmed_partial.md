# Empty ACK Sending Path Is Missing

## Summary

BoringSSL ?? ACK ????? vector???????? records_to_ack ?????????? RFC ??????? ACK ?????

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Relevant section: `7.1 Sending ACKs`

Relevant original English text from the standard:

```text
it may be necessary to send an ACK which does not contain any record numbers.
```

????????? DTLS 1.3 ????????? CID ??????????/?? CID ???????????

## Relevant Source Code

ssl/d1_both.cc:956

```c++
void dtls1_schedule_ack(SSL *ssl) {
  ssl->d1->ack_timer.Stop();
  ssl->d1->sending_ack = !ssl->d1->records_to_ack.empty();
}
```

ssl/d1_both.cc:969

```c++
if (max_plaintext < 2 + 16) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_MTU_TOO_SMALL);  // No room for even one ACK.
  return -1;
}
```

## Implementation Behavior

ACK encoding could represent an empty vector, but dtls1_schedule_ack only sets sending_ack when records_to_ack is non-empty. send_ack also assumes room for at least one 16-byte RecordNumber.

## Inconsistency Reason

Implemented part: Normal ACK generation for processed handshake records is implemented.

Missing or conditional part: Confirmed partial: regular ACK generation works, but the special empty ACK shortcut is not implemented.

## Runtime Evidence

Test source: `test-boringssl/151-187/focused_static_id157_empty_ack.py`

focused_static_id157_empty_ack.py PASS: confirmed sending_ack is gated by !records_to_ack.empty() and no empty-ACK scheduling path exists.

## Impact

The impact is limited to peers or deployments that exercise this specific protocol path. For CID-related findings, peers that require DTLS CID update messages cannot interoperate with this implementation path. For the empty ACK finding, loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Fix Direction

Add an explicit implementation path for the missing protocol behavior, including parser/state-machine support, negative tests, and interop tests. Keep unsupported optional features rejected unless and until their negotiation and message handling are fully implemented.
