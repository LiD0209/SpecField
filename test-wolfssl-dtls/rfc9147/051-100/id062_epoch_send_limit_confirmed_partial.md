# DTLS 1.3 sending epoch limit is not explicitly capped at 2^48-1

## Summary
wolfSSL prevents 64-bit epoch wrap, but the audited code does not explicitly enforce RFC 9147's sending-side epoch limit of 2^48-1. The same root cause affects KeyUpdate response decisions that would advance the sending epoch.

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section 5.8, Key Updates:

```text
sending implementations MUST NOT allow the epoch to exceed 2^48-1.
```

```text
receiving implementations MUST NOT enforce this rule.
```

```text
If a sending implementation receives a KeyUpdate with request_update set to "update_requested", it MUST NOT send its own KeyUpdate if that would cause it to exceed these limits.
```

non-English text removed.

## Relevant Source Code
`src/dtls13.c:2696`

```c
w64Increment(&ssl->dtls13Epoch);

/* Epoch wrapped up */
if (w64IsZero(ssl->dtls13Epoch))
    return BAD_STATE_E;
```

`src/tls13.c:11929`

```c
case update_requested:
    /* New key update requiring a response. */
    ssl->keys.keyUpdateRespond = 1;
    break;
```

## Implementation Behavior
The implementation increments a 64-bit epoch and rejects only wrap-to-zero. It also suppresses overlapping DTLS KeyUpdate while waiting for ACK, but no 2^48-1 limit check was found in the sending epoch increment or KeyUpdate response decision.

## Inconsistency Reason
The 64-bit wrap check implements part of the no-wrap requirement but is much later than RFC 9147's sending-side 2^48-1 limit. A response KeyUpdate decision similarly lacks a check that the response would not exceed the sending limit.

## Runtime Evidence
`verify_wolfssl_dtls13_051_100.py::test_epoch_send_limit_is_64bit_wrap_not_2p48` and `test_keyupdate_response_lacks_2p48_limit_gate` passed. The tests confirm 64-bit wrap checks and KeyUpdate response logic exist, while no explicit 2^48-1 gate is present.

## Impact
The gap is relevant only near extreme KeyUpdate counts, but it is a normative sending-side limit. It can also make KeyUpdate response behavior diverge from the required limits-based suppression rule.

## Fix Direction
Add a helper that checks the sending epoch before any local KeyUpdate or KeyUpdate response can advance it. Reject or terminate the connection when advancing would exceed 2^48-1, while leaving receive-side reconstruction free of that upper-bound enforcement.
