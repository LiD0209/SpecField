# DTLS 1.3 Sending Epoch Limit Is Only Checked for 64-bit Wrap

## Summary

RFC 9147 requires DTLS 1.3 sending implementations to keep the sending epoch at or below `2^48-1`. It also says a sender that receives `KeyUpdate(update_requested)` must not send a response KeyUpdate if doing so would exceed this limit.

wolfSSL represents DTLS 1.3 epochs as a 64-bit `w64wrapper` and does prevent a full 64-bit wrap back to zero. The audited code does not implement an explicit sending-side `2^48-1` epoch limit. The same gap affects `update_requested` responses: the response path checks for an in-flight DTLS KeyUpdate ACK, but it does not check whether the response would advance the sending epoch beyond `2^48-1`.

This confirms IDs 062, 076, 087, and 097 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

RFC 9147 Section 4.2.1, `Sequence Number and Epoch`, defines the no-wrap rule:

```text
Implementations MUST NOT allow the epoch to wrap, but instead MUST establish a new association, terminating the old association.
```

RFC 9147 Section 8, `Key Updates`, defines the stricter sending-side epoch limit:

```text
In order to provide an extra margin of security, sending implementations MUST NOT allow the epoch to exceed 2^48-1.
```

The same paragraph says receivers must not enforce that sender-side cap:

```text
In order to allow this value to be changed later, receiving implementations MUST NOT enforce this rule.
```

It also defines the `update_requested` response rule:

```text
If a sending implementation receives a KeyUpdate with request_update set to "update_requested", it MUST NOT send its own KeyUpdate if that would cause it to exceed these limits and SHOULD instead ignore the "update_requested" flag.
```

These requirements have two distinct parts:

| Requirement | Expected behavior |
|---|---|
| Epoch must not wrap | Stop before the epoch counter wraps |
| Sending epoch must not exceed `2^48-1` | Stop much earlier than 64-bit wrap |
| Receiver must not enforce the `2^48-1` sending limit | Do not reject solely because peer epoch is above that value |
| `update_requested` response must be limit-aware | Ignore `update_requested` if responding would exceed the limit |

## Code Behavior

### Epoch Is Stored as a 64-bit Wrapper

In `D:\project\wolfssl-master\wolfssl\wolfcrypt\types.h`, `w64wrapper` is a 64-bit value or a pair of 32-bit words:

```c
typedef struct w64wrapper {
#if defined(WORD64_AVAILABLE) && !defined(WOLFSSL_W64_WRAPPER_TEST)
    word64 n;
#else
    word32 n[2];
#endif
} w64wrapper;
```

The DTLS 1.3 connection state stores the current sending epoch in `D:\project\wolfssl-master\wolfssl\internal.h`:

```c
w64wrapper dtls13Epoch;
```

This means wolfSSL has enough storage width for the RFC 9147 epoch model.

### KeyUpdate ACK Advances the Sending Epoch

In `D:\project\wolfssl-master\src\dtls13.c`, `Dtls13KeyUpdateAckReceived` advances the DTLS 1.3 sending epoch after the KeyUpdate is acknowledged:

```c
static int Dtls13KeyUpdateAckReceived(WOLFSSL* ssl)
{
    int ret;

    ret = DeriveTls13Keys(ssl, update_traffic_key, ENCRYPT_SIDE_ONLY, 1);
    if (ret != 0)
        return ret;

    w64Increment(&ssl->dtls13Epoch);

    /* Epoch wrapped up */
    if (w64IsZero(ssl->dtls13Epoch))
        return BAD_STATE_E;

    return Dtls13SetEpochKeys(ssl, ssl->dtls13Epoch, ENCRYPT_SIDE_ONLY);
}
```

The implemented check is `w64IsZero` after increment. That catches full 64-bit wrap from `2^64-1` to zero, but it does not catch the RFC 9147 sending limit at `2^48-1`.

For example, incrementing `2^48-1` produces `0x0001000000000000`, not zero. Therefore this code would not reject the first epoch above the RFC sending limit.

### w64Increment Confirms the Boundary

In `D:\project\wolfssl-master\wolfcrypt\src\misc.c`, the 32-bit-pair implementation increments the low word and carries into the high word:

```c
WC_MISC_STATIC WC_INLINE void w64Increment(w64wrapper *n)
{
    n->n[1]++;
    if (n->n[1] == 0)
        n->n[0]++;
}
```

This is a normal 64-bit increment. It has no special case for high word `0x0000ffff` and low word `0xffffffff`, which is the `2^48-1` boundary.

### KeyUpdate Response Path Has No Epoch Limit Gate

In `D:\project\wolfssl-master\src\tls13.c`, `DoTls13KeyUpdate` parses `update_requested` and records that a response is needed:

```c
case update_requested:
    /* New key update requiring a response. */
    ssl->keys.keyUpdateRespond = 1;
    break;
```

For DTLS, it suppresses a new response if another KeyUpdate is already waiting for ACK:

```c
if (ssl->options.dtls && ssl->dtls13WaitKeyUpdateAck) {
    ssl->keys.keyUpdateRespond = 0;
    return 0;
}
```

Otherwise, in the non-threaded path, it sends the response:

```c
return SendTls13KeyUpdate(ssl);
```

In the threaded path, it schedules the response:

```c
ssl->options.sendKeyUpdate = 1;
return 0;
```

The response logic has no check equivalent to “would this response cause the sending epoch to exceed `2^48-1`?”.

### Sending KeyUpdate Has No Pre-send 2^48-1 Gate

In `D:\project\wolfssl-master\src\tls13.c`, `SendTls13KeyUpdate` constructs and sends a KeyUpdate. In DTLS mode it calls `Dtls13HandshakeSend`:

```c
if (ssl->options.dtls) {
    ret = Dtls13HandshakeSend(ssl, output, (word16)outputSz,
        OPAQUE8_LEN + Dtls13GetRlHeaderLength(ssl, 1) +
            DTLS_HANDSHAKE_HEADER_SZ,
        key_update, 0);
}
```

The function contains no explicit `2^48-1` epoch check before sending.

## Runtime Evidence

### Compiled C Harness

I added and compiled a focused C harness:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_epoch_keyupdate_2p48_limit.c
```

Build command run from `D:\project`:

```text
clang D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_epoch_keyupdate_2p48_limit.c -o D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_epoch_keyupdate_2p48_limit.exe
```

The executable was run and its output was saved here:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\repro_epoch_keyupdate_2p48_limit.log
```

Observed output:

```text
INFO increment 2^48-1 -> hi=0x00010000 lo=0x00000000 zero=0
PASS normal epoch allowed by current wolfSSL gate: got=1
PASS 2^48-2 allowed by RFC sender gate: got=1
PASS 2^48-2 allowed by current wolfSSL gate: got=1
PASS 2^48-1 rejected by RFC sender gate: got=0
PASS 2^48-1 still allowed by current wolfSSL gate: got=1
PASS 2^64-1 rejected by current wolfSSL wrap gate: got=0
RESULT confirmed: wrap-to-zero gate permits epoch 2^48, while RFC 9147 sender gate would stop at 2^48-1
```

This harness directly exercises the same boundary condition as the wolfSSL DTLS KeyUpdate epoch path: a zero-after-increment check only fails when the 64-bit counter wraps to zero. It does not fail when `2^48-1` advances to `2^48`.

### Executable Source Probe

I also ran a focused executable Python source probe against the local wolfSSL tree:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\focused_epoch_keyupdate_062_076_087_097_probe.py
```

Saved log:

```text
D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\051-100\focused_epoch_keyupdate_062_076_087_097_probe.log
```

Observed output:

```text
w64wrapper is a 64-bit wrapper: PASS
w64Increment wraps only after full 64-bit range: PASS
Incrementing 2^48-1 does not produce zero: PASS
Incrementing 2^64-1 produces zero: PASS
DTLS KeyUpdate ACK advances sending epoch: PASS
DTLS sending epoch gate is only wrap-to-zero: PASS
No explicit 2^48-1 epoch limit appears in DTLS/TLS protocol source: PASS
SendTls13KeyUpdate has no 2^48-1 pre-send gate: PASS
DoTls13KeyUpdate parses update_requested: PASS
update_requested response path calls or schedules KeyUpdate: PASS
update_requested response path lacks 2^48-1 gate: PASS
DTLS concurrent KeyUpdate ACK gate exists: PASS
RESULT: confirmed partial satisfaction: wolfSSL prevents 64-bit epoch wrap but lacks the RFC9147 sending epoch <= 2^48-1 gate and lacks that gate for update_requested responses
```

I also checked for full wolfSSL unit-test execution. No `unit.test.exe` was found under `D:\project`, and `cl`, `gcc`, `ninja`, `msbuild`, and `mingw32-make` are not available in PATH. Therefore, this turn did not rerun the full wolfSSL unit-test binary. The focused C harness above was compiled and executed in this turn.

## Inconsistency

| ID | Requirement component | wolfSSL behavior | Result |
|---:|---|---|---|
| 062 | Sending epoch must not exceed `2^48-1` | Epoch is incremented as 64-bit and only checked for wrap-to-zero | Partial |
| 076 | Epoch must not wrap and should be stopped before RFC sending cap | Full 64-bit wrap is detected, but the earlier `2^48-1` cap is not | Partial |
| 087 | Same epoch-limit root cause | Same 64-bit wrap-only check | Partial |
| 097 | `update_requested` response must not exceed limit | Response is sent/scheduled unless a DTLS KeyUpdate is already waiting for ACK; no `2^48-1` check | Partial |

The implemented part is real: wolfSSL does not allow the epoch to wrap all the way back to zero, and it does not appear to enforce the sender-side `2^48-1` rule on receive-only epoch reconstruction. The missing part is the required sending-side cap and the corresponding `update_requested` response suppression.

## Root Cause

The DTLS 1.3 epoch model in wolfSSL uses a generic 64-bit counter helper. The sending-side KeyUpdate path treats zero-after-increment as the only terminal condition:

```text
increment epoch -> if epoch == 0, fail
```

RFC 9147 requires a stricter sender-side rule:

```text
before sending with the next epoch, ensure next_epoch <= 2^48-1
```

Those two checks are not equivalent. The 64-bit wrap check permits values from `2^48` through `2^64-1`, which exceed the RFC sending limit.

## Impact

This is an extreme-boundary interoperability and compliance issue. It is only reachable after an unusually large number of KeyUpdates, but it is still a normative DTLS 1.3 sender requirement.

The most direct affected path is a peer sending `KeyUpdate(update_requested)` near the epoch limit. RFC 9147 says the implementation should ignore the request flag if responding would exceed the limit. wolfSSL has no visible decision point for that limit, so the response suppression condition is incomplete.

## Suggested Fix

Add a DTLS 1.3 helper for the sending-side epoch cap, for example:

```text
dtls13_next_epoch_allowed(epoch):
    return epoch < 2^48-1
```

Use it before any local operation that would send a KeyUpdate or advance the sending epoch:

| Location | Required behavior |
|---|---|
| Before sending local KeyUpdate | Reject/terminate before exceeding `2^48-1` |
| Before responding to `update_requested` | Ignore the request flag if the response would exceed the limit |
| After ACK of a sent KeyUpdate | Do not install a sending epoch greater than `2^48-1` |

Keep receive-side epoch reconstruction free of a hard `2^48-1` rejection, because RFC 9147 explicitly says receiving implementations must not enforce that sender-side limit.
