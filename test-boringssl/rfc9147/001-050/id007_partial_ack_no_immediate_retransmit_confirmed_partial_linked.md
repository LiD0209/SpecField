# DTLS 1.3 Partial ACK Does Not Immediately Schedule Retransmission

## Summary

RFC 9147 describes a DTLS 1.3 ACK state machine where receiving a partial ACK should move the implementation back to the `SENDING` state, retransmit the unacknowledged portion of the flight, adjust the retransmit timer, and return to `WAITING`.

BoringSSL implements important parts of this behavior. It parses DTLS 1.3 ACK records, maps acknowledged record numbers back to outgoing handshake message fragments, marks those ranges as acknowledged, skips acknowledged ranges during later retransmission, and cancels retransmission once the full flight is acknowledged.

The partial ACK path is incomplete. When only part of the outgoing flight is acknowledged, `dtls1_process_ack` records the ACKed ranges and clears unused write epochs, but it does not immediately set `sending_flight`, does not start or re-arm the retransmit timer, and contains a `TODO` to schedule a retransmit. The unacknowledged portion can still be retransmitted later through the existing timer-expiry path, but not immediately when the partial ACK is received. This confirms RFC 9147 ID 007 as **partially satisfied**.

## Standard Requirement

RFC 9147, Section 5.8.1, "State Machine":

```text
The implementation reads an ACK from the peer: upon receiving an
ACK for a partial flight (as mentioned in Section 7.1), the
implementation transitions to the SENDING state, where it
retransmits the unacknowledged portion of the flight, adjusts and
re-arms the retransmit timer, and returns to the WAITING state.
Upon receiving an ACK for a complete flight, the implementation
cancels all retransmissions and either remains in WAITING, or, if
the ACK was for the final flight, transitions to FINISHED.
```

RFC 9147, Section 7.2, "Receiving ACKs":

```text
When an implementation receives an ACK, it SHOULD record that the
messages or message fragments sent in the records being ACKed were
received and omit them from any future retransmissions. Upon receipt
of an ACK that leaves it with only some messages from a flight having
been acknowledged, an implementation SHOULD retransmit the
unacknowledged messages or fragments. Note that this requires
implementations to track which messages appear in which records.
Once all the messages in a flight have been acknowledged, the
implementation MUST cancel all retransmissions of that flight.
```

The expected ACK lifecycle is:

| ACK state | Expected behavior |
|---|---|
| ACK covers one or more sent records | Mark the corresponding messages or fragments as acknowledged |
| ACK covers only part of a flight | Retransmit the unacknowledged messages or fragments |
| Partial ACK is received while waiting | Transition to `SENDING`, adjust and re-arm the retransmit timer, then return to `WAITING` |
| ACK covers the full flight | Cancel retransmission for that flight |

## Code Behavior

### ACK Parsing and Range Marking Are Implemented

In `ssl/d1_pkt.cc`, `dtls1_process_ack` parses the ACK record's `RecordNumber` list:

```cpp
while (CBS_len(&record_numbers) != 0) {
  uint64_t epoch, seq;
  if (!CBS_get_u64(&record_numbers, &epoch) ||
      !CBS_get_u64(&record_numbers, &seq)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_DECODE_ERROR);
    *out_alert = SSL_AD_DECODE_ERROR;
    return ssl_open_record_error;
  }
```

After finding the matching sent record, BoringSSL marks the corresponding outgoing message ranges as acknowledged:

```cpp
// Mark each message as ACKed.
if (sent_record->first_msg == sent_record->last_msg) {
  ssl->d1->outgoing_messages[sent_record->first_msg].acked.MarkRange(
      sent_record->first_msg_start, sent_record->last_msg_end);
} else {
  ssl->d1->outgoing_messages[sent_record->first_msg].acked.MarkRange(
      sent_record->first_msg_start, SIZE_MAX);
```

This satisfies the part of RFC 9147 Section 7.2 that requires implementations to record which messages or fragments were received and omit them from future retransmissions.

### Complete ACK Cancels Retransmission

In the same function, once all outgoing messages in the flight have been fully acknowledged, BoringSSL stops the retransmit timer and clears the outgoing flight:

```cpp
if (std::all_of(ssl->d1->outgoing_messages.begin(),
                ssl->d1->outgoing_messages.end(),
                [](const auto &msg) { return msg.IsFullyAcked(); })) {
  dtls1_stop_timer(ssl);
  dtls_clear_outgoing_messages(ssl);
```

This matches the RFC 9147 requirement that a complete ACK cancels all retransmissions for the flight.

### Partial ACK Does Not Immediately Trigger Retransmission

The incomplete behavior is in the partial ACK branch:

```cpp
} else {
  // We may still be able to drop unused write epochs.
  dtls_clear_unused_write_epochs(ssl);

  // TODO(crbug.com/383016430): Schedule a retransmit. The peer will have
  // waited before sending the ACK, so a partial ACK suggests packet loss.
}
```

This branch does not set:

```cpp
ssl->d1->sending_flight = true;
```

It also does not call a timer start or re-arm path such as:

```cpp
retransmit_timer.StartMicroseconds(...)
dtls1_start_timer(...)
```

The `TODO` directly identifies the missing behavior: the implementation should schedule a retransmit when the partial ACK indicates packet loss.

### Selective Retransmission Data Path Exists

In `ssl/d1_both.cc`, the send path iterates over unacknowledged ranges:

```cpp
// Iterate over every un-acked range in the message, if any.
Span<const uint8_t> body = body_cbs;
for (;;) {
  auto range = msg.acked.NextUnmarkedRange(ssl->d1->outgoing_offset);
```

This means the data structures for selective retransmission exist. The issue is not that BoringSSL cannot identify unacknowledged fragments. The issue is that a partial ACK does not immediately enter the send path.

### Current Retransmission Scheduling Depends on Timer Expiry

In `ssl/d1_lib.cc`, the regular timer-expiry path sets `sending_flight`:

```cpp
if (ssl->d1->retransmit_timer.IsExpired(now)) {
  any_timer_expired = true;
  ssl->d1->sending_flight = true;
  ssl->d1->retransmit_timer.Stop();
```

In `ssl/d1_both.cc`, `dtls1_flush` only sends a pending flight when `sending_flight` is true:

```cpp
// Send the pending flight, if any.
if (ssl->d1->sending_flight) {
  int ret = send_flight(ssl);
  if (ret <= 0) {
    return ret;
  }
```

Therefore, after a partial ACK, the unacknowledged data can be retransmitted later through the existing retransmit timer path. It is not scheduled immediately by ACK processing.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\001-050\repro_dtls13_partial_ack_no_immediate_retransmit_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\001-050 -B D:\project\SpecTrace\test-boringssl\rfc9147\001-050\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\001-050\build-linked-probe --config Release --target repro_dtls13_partial_ack_no_immediate_retransmit_linked_probe
D:\project\SpecTrace\test-boringssl\rfc9147\001-050\build-linked-probe\Release\repro_dtls13_partial_ack_no_immediate_retransmit_linked_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\001-050\repro_dtls13_partial_ack_no_immediate_retransmit_linked_probe.log
```

Observed output:

```text
linked BoringSSL DTLS_method successfully
ok: d1_pkt.cc contains dtls1_process_ack
ok: d1_pkt.cc contains CBS_get_u64(&record_numbers, &epoch)
ok: d1_pkt.cc contains acked.MarkRange
ok: d1_pkt.cc contains dtls1_stop_timer(ssl)
ok: d1_pkt.cc contains Schedule a retransmit
ok: partial ACK branch contains dtls_clear_unused_write_epochs(ssl)
ok: partial ACK branch does not contain sending_flight = true
ok: partial ACK branch does not contain retransmit_timer.Start
ok: partial ACK branch does not contain dtls1_start_timer
ok: d1_both.cc contains NextUnmarkedRange
ok: d1_both.cc contains if (ssl->d1->sending_flight)
ok: d1_both.cc contains retransmit_timer.StartMicroseconds
ok: d1_lib.cc contains retransmit_timer.IsExpired
ok: d1_lib.cc contains ssl->d1->sending_flight = true
RESULT: confirmed partial. ACKed ranges are tracked, but the partial ACK branch does not immediately schedule retransmit; existing timer expiry is the observed scheduling path.
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks the relevant product-source predicates for ACK parsing, ACK range marking, complete-flight cancellation, partial-ACK scheduling, selective retransmission, and timer-based retransmission.

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Record which messages or fragments were acknowledged | Implemented with `acked.MarkRange` |
| Omit acknowledged fragments from future retransmissions | Implemented through `NextUnmarkedRange` |
| Cancel retransmission when the full flight is acknowledged | Implemented with `dtls1_stop_timer` and outgoing-flight cleanup |
| On partial ACK, transition to `SENDING` | Not implemented in the partial ACK branch |
| On partial ACK, retransmit the unacknowledged portion promptly | Not scheduled immediately |
| On partial ACK, adjust and re-arm the retransmit timer | Not implemented in the partial ACK branch |

The result is partial satisfaction. BoringSSL has ACK tracking and selective retransmission machinery, but the partial ACK path does not immediately drive that machinery.

## Root Cause

The ACK processing code and the retransmission code are connected through `sending_flight` and the retransmit timer. The complete ACK path stops retransmission correctly, and the timer-expiry path can later trigger retransmission. However, the partial ACK branch in `dtls1_process_ack` does not set the sending state or restart the timer.

The missing transition is:

```text
partial ACK received
  mark ACKed ranges
  schedule immediate retransmission of unacknowledged ranges
  adjust and re-arm retransmit timer
```

The source currently stops after marking ACKed ranges and clearing unused write epochs.

## Impact

This is a DTLS 1.3 retransmission-latency and protocol-state-machine conformance issue.

| Impact area | Description |
|---|---|
| Protocol conformance | The partial ACK path does not follow RFC 9147's immediate transition to `SENDING`. |
| Loss recovery | Recovery of the missing fragments may wait for the existing retransmit timer instead of reacting to the partial ACK. |
| Handshake latency | Packet loss during large or fragmented flights can take longer to repair. |
| Existing correctness | Already ACKed ranges are still tracked and omitted from later retransmissions. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as incomplete immediate retransmission scheduling after partial ACK.

## Suggested Fix

Update the partial ACK branch in `dtls1_process_ack` to schedule retransmission of the unacknowledged ranges instead of waiting for timer expiry.

At minimum, the implementation should:

| Required behavior | Expected effect |
|---|---|
| Set `ssl->d1->sending_flight = true` or equivalent | Causes `dtls1_flush` to enter the send path |
| Recompute or adjust the retransmit timeout | Matches RFC 9147's timer adjustment requirement |
| Re-arm the retransmit timer | Avoids stale timer state after partial ACK processing |
| Preserve ACKed range marking | Ensures retransmission sends only unacknowledged fragments |
| Add runner or unit coverage for partial ACK | Pins immediate scheduling behavior |
