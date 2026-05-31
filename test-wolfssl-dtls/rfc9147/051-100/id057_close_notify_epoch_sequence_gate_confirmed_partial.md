# DTLS 1.3 close_notify Does Not Preserve the Epoch/Sequence Boundary

## Summary

RFC 9147 requires a DTLS 1.3 receiver to ignore data whose epoch/sequence number pair is after the pair of a valid received closure alert.

wolfSSL does implement close_notify as a connection shutdown signal: it records that close_notify was received and returns `ZERO_RETURN` from the current read path. However, the audited code does not store the close_notify record's epoch/sequence number pair and does not compare later records against that boundary.

This confirms ID 057 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

The user request cites RFC 9147 Section 5.8, but the close_notify ordering requirement is in RFC 9147 Section 5.10, `Alert Messages`. Section 5.8 covers timeouts and retransmission.

RFC 9147 Section 5.10 says:

```text
Any data received with an epoch/sequence number pair after that of a
valid received closure alert MUST be ignored.
```

The same paragraph explains the DTLS-specific ordering rule:

```text
Note: this is a change from TLS 1.3 which depends on the order of receipt
rather than the epoch and sequence number.
```

This is not only an API shutdown state requirement. A DTLS receiver needs the valid closure alert's record-number boundary so it can ignore later data by epoch/sequence pair.

## Code Behavior

### Current Record Epoch and Sequence Are Tracked

In `D:\project\wolfssl-master\wolfssl\internal.h`, wolfSSL stores the current received DTLS record number:

```c
word16 curEpoch;    /* Received epoch in current record    */
word16 curSeq_hi;   /* Received sequence in current record */
word32 curSeq_lo;

#ifdef WOLFSSL_DTLS13
w64wrapper curEpoch64;    /* Received epoch in current record    */
w64wrapper curSeq;
#endif /* WOLFSSL_DTLS13 */
```

This means the record parser has access to the epoch/sequence pair for the current DTLS 1.3 record.

### close_notify Is Stored Only as a Boolean State

In `D:\project\wolfssl-master\wolfssl\internal.h`, the connection options contain a single close-notify bit:

```c
word16            closeNotify:1;      /* we've received a close notify */
```

There is no adjacent `closeNotifyEpoch`, `closeNotifySeq`, `closureEpoch`, or similar field that would preserve the boundary pair required by RFC 9147.

### DoAlert Marks close_notify as Received

In `D:\project\wolfssl-master\src\internal.c`, `DoAlert` parses the alert and records close_notify:

```c
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}
```

This satisfies the basic close_notify state handling requirement.

### The Alert Dispatch Returns ZERO_RETURN

In `D:\project\wolfssl-master\src\internal.c`, the alert dispatch path treats close_notify as a clean shutdown signal:

```c
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx =
        ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```

This is useful shutdown behavior, but it does not itself prove that later data is ignored by comparing epoch/sequence pairs against the closure alert pair.

### Tests Cover Shutdown, Not the RFC 9147 Pair Boundary

The local wolfSSL tests include close_notify and DTLS shutdown coverage. For example, `D:\project\wolfssl-master\tests\api.c` checks that a peer receives `WOLFSSL_ERROR_ZERO_RETURN` and that the last alert is `close_notify`.

The DTLS helper in `D:\project\wolfssl-master\tests\api\test_dtls.c` also exercises ordinary DTLS shutdown. These tests cover the API-level close_notify behavior, but they do not inject data records after a valid closure alert and verify an epoch/sequence pair comparison.

## Runtime Evidence

### Compiled C Harness

I added a focused C harness:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_close_notify_057_epoch_sequence_source_check.c
```

Build command run from `D:\project`:

```text
D:\LLVM\bin\clang.exe D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_close_notify_057_epoch_sequence_source_check.c -o D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_close_notify_057_epoch_sequence_source_check.exe
```

The executable was run and its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_close_notify_057_epoch_sequence_source_check.log
```

Observed output:

```text
PASS closeNotify state bit exists
PASS DTLS current record epoch/sequence fields exist
PASS DoAlert sets closeNotify on close_notify
PASS record alert dispatch returns ZERO_RETURN on close_notify
PASS no stored closure alert epoch/sequence boundary fields
PASS no RFC closure-boundary wording in receive implementation
RESULT confirmed: close_notify is handled as shutdown state, but no stored closure epoch/sequence boundary was found
```

This is a compiled source-behavior harness. It verifies the implemented close_notify path and the absence of the structural state needed to enforce the RFC 9147 boundary. I did not rerun a full wolfSSL unit-test binary in this turn because no reusable `unit.test.exe` or `wolfssl.lib` was present under `D:\project\wolfssl-master`, and the existing CMake cache shows `CMAKE_MAKE_PROGRAM-NOTFOUND`.

## Inconsistency

| Requirement component | wolfSSL behavior | Result |
|---|---|---|
| Treat close_notify as connection closure | `DoAlert` sets `ssl->options.closeNotify`; alert dispatch returns `ZERO_RETURN` | Satisfied |
| Preserve the valid closure alert's epoch/sequence pair | Current record pair exists as `curEpoch64`/`curSeq`, but no closure-boundary pair is stored | Missing |
| Ignore later data by comparing epoch/sequence pair | No close_notify boundary comparison was found in the audited receive implementation | Missing |

The mismatch is therefore partial: wolfSSL implements close_notify shutdown state, but the audited DTLS 1.3 path does not implement the RFC 9147 record-number boundary rule.

## Root Cause

The close_notify path reduces the received closure alert to a boolean state:

```text
received close_notify -> closeNotify = 1 -> return ZERO_RETURN
```

RFC 9147 requires a more specific DTLS state transition:

```text
received valid close_notify at (epoch, sequence)
    -> store closure boundary
    -> ignore any later data whose pair is after that boundary
```

Because the boundary pair is not retained, the implementation has no visible state against which later data records can be compared.

## Impact

This affects the DTLS 1.3 behavior after a valid closure alert. Peers that send reordered or delayed records around close_notify rely on the receiver applying the RFC's epoch/sequence ordering rule. Without an explicit stored boundary, the behavior depends on general shutdown handling rather than the normative DTLS record-number comparison.

## Suggested Fix

Store the epoch and sequence number of the valid received close_notify alert in DTLS 1.3 connection state. Then, in the DTLS 1.3 record receive path, before dispatching application data or other post-close records, compare the reconstructed record pair against the stored closure boundary and ignore records that are after it.
