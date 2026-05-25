# Empty ACK Sending Path Is Missing

## Summary

RFC 9147 allows an ACK to be sent even when it contains no record numbers. BoringSSL can encode the ACK vector format, but its scheduler only sends ACKs when `records_to_ack` is non-empty, so there is no product path for the special empty ACK case.

This confirms ID 157 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `7.1 Sending ACKs`

Original English requirement excerpt:

```text
it may be necessary to send an ACK which does not contain any record numbers.
```

## Code Behavior

In `ssl/d1_both.cc`, ACK scheduling is gated by a non-empty record list:

```cpp
void dtls1_schedule_ack(SSL *ssl) {
  ssl->d1->ack_timer.Stop();
  ssl->d1->sending_ack = !ssl->d1->records_to_ack.empty();
}
```

`send_ack` also assumes enough space for at least one RecordNumber:

```cpp
if (max_plaintext < 2 + 16) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_MTU_TOO_SMALL);  // No room for even one ACK.
  return -1;
}
```

## Runner Coverage

The runner can encode and inspect DTLS ACK records in DTLS 1.3 tests, but it does not change the product scheduling condition in `libssl`.

## Runtime Evidence

Focused static test:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\151-187\focused_static_id157_empty_ack.py
```

Linked probe log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\151-187\repro_dtls13_151_187_linked_probe.log
```

Observed output excerpt:

```text
ID157 ACK encoding uses a length-prefixed vector: PASS
ID157 ACK scheduling is gated by non-empty records_to_ack: PASS
ID157 send_ack assumes space for at least one RecordNumber: PASS
```

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Allow sending ACK with no record numbers | Scheduler only sends ACKs when records_to_ack is non-empty |
| Support special empty ACK case | No empty-ACK scheduling path found |

## Root Cause

BoringSSL implements ordinary DTLS ACK generation, but not the special empty ACK shortcut described in RFC 9147.

## Impact

Loss recovery may wait for retransmission timeout instead of being shortened by an empty ACK.

## Suggested Fix

Add an ACK scheduling branch that can emit a valid empty ACK when the protocol state requires it.
