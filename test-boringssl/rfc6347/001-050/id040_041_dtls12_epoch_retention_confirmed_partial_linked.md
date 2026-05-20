# DTLS 1.2 Previous Read Epoch Retention Is Only Partially Implemented

## Summary

RFC 6347 allows DTLS implementations to retain previous epoch keying material for a limited time so that reordered records from an older epoch can still be accepted. The RFC also says old-epoch packets should generally be discarded after the transition, but retention for up to the default MSL is allowed when packet loss or reordering would otherwise cause problems.

BoringSSL implements the core epoch and sequence-number machinery, and it does retain a previous read epoch in the DTLS 1.3 path. However, the DTLS 1.2 read path immediately replaces the active read epoch and the DTLS 1.2 record parser only considers the current read epoch. There is no DTLS 1.2 previous-read-epoch retention window comparable to the DTLS 1.3 path.

This confirms IDs 040 and 041 as **partially satisfied** with the same root cause.

## Standard Requirement

RFC 6347, Section 4.1, "The DTLS Record Layer":

```text
DTLS uses an explicit sequence number, rather than an implicit one,
carried in the sequence_number field of the record.  Sequence numbers
are maintained separately for each epoch, with each sequence_number
initially being 0 for each epoch.
```

RFC 6347 explains why epochs matter across cipher-state changes:

```text
If several handshakes are performed in close succession, there might
be multiple records on the wire with the same sequence number but
from different cipher states.  The epoch field allows recipients to
distinguish such packets.
```

The same section contains the key epoch-retention guidance:

```text
In order to ensure that any given sequence/epoch pair is unique,
implementations MUST NOT allow the same epoch value to be reused
within two times the TCP maximum segment lifetime.
```

```text
Note that because DTLS records may be reordered, a record from epoch
1 may be received after epoch 2 has begun.  In general,
implementations SHOULD discard packets from earlier epochs, but if
packet loss causes noticeable problems they MAY choose to retain
keying material from previous epochs for up to the default MSL
specified for TCP [TCP] to allow for packet reordering. ... Until the
handshake has completed, implementations MUST accept packets from the
old epoch.
```

RFC 6347 also forbids epoch wrap:

```text
Similarly, implementations MUST NOT allow the epoch to wrap, but
instead MUST establish a new association, terminating the old
association as described in Section 4.2.8.
```

The expected behavior is:

| State | Expected behavior |
|---|---|
| Handshake not complete | Accept packets from the old epoch |
| Epoch transition completed | Usually discard earlier-epoch packets |
| Packet loss or reordering causes issues | May retain previous epoch keying material for up to the default MSL |
| Epoch wrap would occur | Do not allow wrap; establish a new association |

## Code Behavior

### DTLS 1.2 Read State Is Replaced Immediately

In `ssl/dtls_method.cc`, BoringSSL distinguishes DTLS 1.2 from DTLS 1.3 when applying read epochs:

```cpp
    // In DTLS 1.3, new read epochs are not applied immediately. In principle,
    // we could do the same in DTLS 1.2, but we would ignore every record from
    // the previous epoch anyway.
    assert(ssl->d1->next_read_epoch == nullptr);
    ssl->d1->next_read_epoch = MakeUnique<DTLSReadEpoch>(std::move(new_epoch));
```

For DTLS 1.2, the active read epoch is replaced immediately:

```cpp
  } else {
    ssl->d1->read_epoch = std::move(new_epoch);
    ssl->d1->has_change_cipher_spec = false;
  }
```

This means BoringSSL does not retain a DTLS 1.2 previous-read-epoch window.

### DTLS 1.2 Parser Only Considers One Read Epoch

In `ssl/dtls_record.cc`, BoringSSL says the DTLS 1.2 parser only needs to consider one epoch:

```cpp
  // Look up the corresponding epoch. In DTLS 1.2, we only need to consider one
  // epoch.
  if (epoch == ssl->d1->read_epoch.epoch &&
      !use_dtls13_record_header(ssl, epoch)) {
    out->read_epoch = &ssl->d1->read_epoch;
  }
```

If no matching read epoch is found, the record is discarded:

```cpp
  if (record.read_epoch == nullptr ||
      record.read_epoch->bitmap.ShouldDiscard(record.number.sequence())) {
    // Drop this record. It's from an unknown epoch or is a replay.
```

So once DTLS 1.2 replaces `read_epoch`, a reordered old-epoch record has no retained read epoch to match and is dropped as unknown.

### DTLS 1.3 Has Previous Read Epoch Retention

The same source file contains explicit DTLS 1.3 retention logic:

```cpp
  // Once we receive a record from the next epoch in DTLS 1.3, it becomes the
  // current epoch. Also save the previous epoch. This allows us to handle
  // packet reordering on KeyUpdate, as well as ACK retransmissions of the
  // Finished flight.
```

```cpp
    prev->epoch = std::move(ssl->d1->read_epoch);
    ssl->d1->prev_read_epoch = std::move(prev);
    ssl->d1->read_epoch = std::move(*ssl->d1->next_read_epoch);
```

In `ssl/internal.h`, the previous read epoch is documented as DTLS 1.3 only:

```cpp
  // next_read_epoch is the next read epoch in DTLS 1.3. It will become
  // current once a record is received from it.
  UniquePtr<DTLSReadEpoch> next_read_epoch;

  // prev_read_epoch is the previous read epoch in DTLS 1.3.
  UniquePtr<DTLSPrevReadEpoch> prev_read_epoch;
```

This confirms the contrast in the audit item: BoringSSL has a previous-read-epoch mechanism, but it is scoped to DTLS 1.3.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS tests:

```go
addDTLSRetransmitTests()
```

The repository's runner exercises DTLS record handling and retransmit scenarios, but the relevant code in the product stack still distinguishes DTLS 1.2 and DTLS 1.3 retention behavior as above.

The runner coverage does not change the product-code fact that DTLS 1.2 read-state transitions replace the active read epoch directly while the previous-read-epoch retention window exists only for DTLS 1.3.

## Runtime Evidence

A linked probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\repro_dtls12_epoch_retention_linked_probe.cpp
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```text
cmake --build D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe --config Release --target repro_dtls12_epoch_retention_linked_probe
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\build-linked-probe\Release\repro_dtls12_epoch_retention_linked_probe.exe D:\project\boringssl-main
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc6347\001-050\repro_dtls12_epoch_retention_linked_probe.log
```

Observed output:

```text
LINK SSL_CTX_new(DTLS_method): PASS
LINK DTLS1_2_VERSION min/max: PASS
LINK OpenSSL_version: BoringSSL
DTLS 1.2 read state directly replaces read_epoch: PASS
Source comment says DTLS 1.2 would ignore previous epoch: PASS
DTLS 1.3 read state is staged in next_read_epoch: PASS
DTLS 1.2 parser only considers one read epoch: PASS
Unknown or stale epoch records are discarded: PASS
DTLS 1.3 promotion retains previous read epoch: PASS
internal.h marks previous read epoch as DTLS 1.3 only: PASS
Epoch wrap protection is present: PASS

EXIT_CODE: 0
```

The probe links against BoringSSL and checks the source predicates for DTLS 1.2 direct read-epoch replacement, DTLS 1.3 previous-read-epoch retention, record discarding, and epoch-wrap protection.

## Inconsistency

| RFC 6347 behavior | BoringSSL behavior |
|---|---|
| Old-epoch packets may be retained for a limited window | DTLS 1.2 read state is replaced immediately |
| Until handshake completes, old-epoch packets must be accepted | DTLS 1.2 parser only considers the current read epoch |
| Earlier-epoch packets may be tolerated up to the default MSL | No DTLS 1.2 previous-read-epoch retention window is retained |
| Epoch wrap must not occur | Wrap protection exists |

The issue is therefore not a total lack of epoch handling. The confirmed gap is that DTLS 1.2 does not retain the previous read epoch in the way DTLS 1.3 does.

## Root Cause

BoringSSL uses different read-epoch policies for DTLS 1.2 and DTLS 1.3.

| Protocol | Read-epoch policy |
|---|---|
| DTLS 1.2 | Replace the active read epoch immediately |
| DTLS 1.3 | Stage the next epoch, then retain the previous read epoch once the new one becomes active |

That difference explains IDs 040 and 041:

| ID | Root cause mapping |
|---|---|
| 040 | DTLS 1.2 read state replaces the current epoch without a previous-epoch retention window |
| 041 | Same root cause as ID040 |

## Impact

This is a DTLS 1.2 read-path robustness and conformance issue.

| Impact area | Description |
|---|---|
| Packet reordering | Reordered old-epoch packets can be dropped once DTLS 1.2 read state advances. |
| MSL-style retention | The DTLS 1.2 path lacks the previous-epoch retention window that RFC 6347 permits for robustness. |
| Protocol comparison | DTLS 1.3 has previous-read-epoch retention, but DTLS 1.2 does not. |
| Test coverage | The runner does not alter the product-code distinction between the two protocol versions. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as missing DTLS 1.2 previous-read-epoch retention in the product read path.

## Suggested Fix

If BoringSSL wants to align the DTLS 1.2 path with the robustness permitted by RFC 6347, it would need to retain previous read-epoch keying material for a bounded window after the transition, rather than replacing the active read epoch immediately.

| Required change | Expected effect |
|---|---|
| Add a DTLS 1.2 previous-read-epoch retention window | Allows reordered old-epoch packets to be accepted for a bounded time |
| Consult retained previous read epochs during parsing | Stops immediately discarding all old-epoch records after a transition |
| Preserve wrap protection | Keeps the existing no-epoch-wrap invariant |
| Add runner coverage for reordered old-epoch packets | Pins the intended DTLS 1.2 retention behavior |
