# DTLS 1.2 Previous Epoch Retention Partially Implemented

## Summary

BoringSSL retains previous read epochs for DTLS 1.3, but the DTLS 1.2 read-state transition directly replaces the current read epoch. RFC 6347 requires implementations to tolerate old-epoch packets during handshake transitions and discusses avoiding epoch reuse while old packets may still arrive. The audited DTLS 1.2 path therefore only partially satisfies the epoch retention requirements.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc6347

Section: RFC 6347 Section 4.1, Record Layer

```text
"Each epoch has a separate sequence number space."
"epoch number is initially zero"
```

RFC 6347 also requires implementations to handle records from earlier epochs during handshake transitions and avoid unsafe epoch reuse while delayed packets may still be valid on the network.

## Relevant Source Code

`ssl/dtls_method.cc:96`

```c++
    // In DTLS 1.3, new read epochs are not applied immediately. In principle,
    // we could do the same in DTLS 1.2, but we would ignore every record from
    // the previous epoch anyway.
```

`ssl/dtls_method.cc:104`

```c++
  } else {
    ssl->d1->read_epoch = std::move(new_epoch);
    ssl->d1->has_change_cipher_spec = false;
  }
```

`ssl/dtls_record.cc:257`

```c++
  // Look up the corresponding epoch. In DTLS 1.2, we only need to consider one
  // epoch.
  if (epoch == ssl->d1->read_epoch.epoch &&
      !use_dtls13_record_header(ssl, epoch)) {
```

`ssl/dtls_record.cc:368`

```c++
  // Once we receive a record from the next epoch in DTLS 1.3, it becomes the
  // current epoch. Also save the previous epoch. This allows us to handle
  // packet reordering on KeyUpdate, as well as ACK retransmissions of the
  // Finished flight.
```

`ssl/dtls_record.cc:388`

```c++
    prev->epoch = std::move(ssl->d1->read_epoch);
    ssl->d1->prev_read_epoch = std::move(prev);
```

The code explicitly distinguishes DTLS 1.3 retention from DTLS 1.2 behavior. DTLS 1.2 lookup only considers one read epoch and discards records from unrecognized epochs.

## Implementation Behavior

Implemented part: BoringSSL initializes epoch zero, advances epochs on cipher-state changes, uses separate record numbers per write epoch, and checks epoch/sequence overflow. DTLS 1.3 has `next_read_epoch` and `prev_read_epoch` handling.

Missing or condition-dependent part: DTLS 1.2 does not retain a previous read epoch after `ChangeCipherSpec`; it immediately replaces `ssl->d1->read_epoch`. The record parser then only matches the current epoch for DTLS 1.2. Reordered packets from the previous epoch are dropped rather than accepted during the transition window.

## Inconsistency Reason

The RFC 6347 requirement applies to DTLS 1.2. BoringSSL has the relevant retention mechanism only in the newer DTLS 1.3 path. The DTLS 1.2 branch comments that it would ignore the previous epoch and the record parser confirms only one epoch is considered. This makes the requirement confirmed partial: general epoch machinery exists, but DTLS 1.2 previous-epoch retention is absent.

## Runtime Evidence

Focused verification script: `verify_dtls12_cookie_paths.py`

Log: `verify_dtls12_cookie_paths.log`

Result summary:

```text
passed=true
DTLS 1.2 read epoch is replaced instead of retained
handshake fragmentation and transcript header paths present
```

No prebuilt BoringSSL test binary was present, so the verification used executable source checks over the audited DTLS state-transition and record parser files.

## Impact

Under packet reordering around DTLS 1.2 cipher-state changes, valid records from the previous epoch may be dropped. DTLS can recover some loss via retransmission, but this narrows tolerance compared with the RFC's old-epoch handling guidance.

## Fix Direction

Consider extending previous-epoch retention to DTLS 1.2 read-state transitions. The record parser would need to consult current and retained previous epochs, enforce replay protection per epoch, and expire old epoch material after the appropriate packet lifetime. Add tests that inject reordered previous-epoch records after a read-state change.
