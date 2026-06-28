# DTLS 1.3 Post-Handshake message_seq Continuity Is Not Preserved by the Generic DTLS Finished Reset Path

## Summary  [non-English text removed]

This report covers ID 139.

RFC 9147 requires DTLS 1.3 `message_seq` to continue across post-handshake messages. Unlike DTLS 1.2 renegotiation, DTLS 1.3 must not reset `message_seq` for post-handshake exchanges, because the receiver needs to distinguish a retransmission of an earlier post-handshake message from a newly generated post-handshake message.

wolfSSL has a shared DTLS 1.3 handshake sender. `NewSessionTicket` and `KeyUpdate` both use `Dtls13HandshakeSend()`, and DTLS 1.3 handshake headers take `message_seq` from `ssl->keys.dtls_handshake_number`. However, the generic DTLS `SendFinished()` and `DoFinished()` paths reset `ssl->keys.dtls_handshake_number` to zero after the main handshake, without a guard excluding DTLS 1.3. A post-handshake `NewSessionTicket` or `KeyUpdate` sent after that reset will therefore use the reset counter.

This confirms ID 139 as a real **partial consistency issue**. The finding is stronger than "not proven": the audited source shows a plausible reset path that conflicts with RFC 9147's continuity rule.

## Standard Requirement

Official standard: [https://www.rfc-editor.org/rfc/rfc9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: RFC 9147 Section 5.5, `Handshake Message Format and Reordering`.

Relevant original English text from RFC 9147:

```text
uint16 message_seq;        /* DTLS-required field */
```

```text
The first message each side transmits in each association always has message_seq = 0.
```

```text
Whenever a new message is generated, the message_seq value is incremented by one.
```

```text
When a message is retransmitted, the old message_seq value is reused, i.e., not incremented.
```

```text
However, in DTLS 1.3 the message_seq is not reset, to allow distinguishing a retransmission from a previously sent post-handshake message from a newly sent post-handshake message.
```

Relevant section: RFC 9147 Section 5.8.4, `State Machine Duplication for Post-Handshake Messages`.

```text
DTLS 1.3 makes use of the following categories of post-handshake messages:

1.  NewSessionTicket

2.  KeyUpdate

3.  NewConnectionId

4.  RequestConnectionId

5.  Post-handshake client authentication
```

```text
Messages of each category can be sent independently, and reliability is established via independent state machines, each of which behaves as described in Section 5.8.1.
```

The important compliance point for ID 139 is that post-handshake messages are new DTLS handshake messages within the same association. Their `message_seq` values must continue from the existing per-side sequence, not restart at zero.

## Relevant Source Code

### DTLS 1.3 Headers Use dtls_handshake_number as message_seq

`D:\project\wolfssl-master\src\dtls13.c:1292`

```c
int Dtls13HandshakeAddHeader(WOLFSSL* ssl, byte* output,
    enum HandShakeType msg_type, word32 length)
```

`D:\project\wolfssl-master\src\dtls13.c:1301`

```c
c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);
```

The fragmented header path uses the same counter:

`D:\project\wolfssl-master\src\dtls13.c:192`

```c
static int Dtls13HandshakeAddHeaderFrag(WOLFSSL* ssl, byte* output,
    enum HandShakeType msg_type, word32 frag_offset, word32 frag_length,
    word32 msg_length)
```

`D:\project\wolfssl-master\src\dtls13.c:202`

```c
c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);
```

### New Sends Increment the Counter

`D:\project\wolfssl-master\src\dtls13.c:2063`

```c
int Dtls13HandshakeSend(WOLFSSL* ssl, byte* message, word16 outputSize,
    word16 length, enum HandShakeType handshakeType, int hashOutput)
```

`D:\project\wolfssl-master\src\dtls13.c:2119`

```c
if (ret == 0 || ret == WC_NO_ERR_TRACE(WANT_WRITE))
    ssl->keys.dtls_handshake_number++;
```

`D:\project\wolfssl-master\src\dtls13.c:2126`

```c
if (ret == 0)
    ssl->keys.dtls_handshake_number++;
```

This is the normal DTLS 1.3 behavior: a newly sent message consumes a new `message_seq`.

### KeyUpdate Uses the Same DTLS 1.3 Sender

`D:\project\wolfssl-master\src\tls13.c:12145`

```c
int SendTls13KeyUpdate(WOLFSSL* ssl)
```

`D:\project\wolfssl-master\src\tls13.c:12189`

```c
ret = Dtls13HandshakeSend(ssl, output, (word16)outputSz,
    OPAQUE8_LEN + Dtls13GetRlHeaderLength(ssl, 1) +
        DTLS_HANDSHAKE_HEADER_SZ,
    key_update, 0);
```

Therefore DTLS 1.3 `KeyUpdate` uses `ssl->keys.dtls_handshake_number` for its `message_seq`.

### NewSessionTicket Uses the Same DTLS 1.3 Sender

`D:\project\wolfssl-master\src\tls13.c:12741`

```c
static int SendTls13NewSessionTicket(WOLFSSL* ssl)
```

`D:\project\wolfssl-master\src\tls13.c:12898`

```c
return Dtls13HandshakeSend(ssl, output, (word16)sendSz,
                           (word16)idx, session_ticket, 0);
```

Therefore DTLS 1.3 `NewSessionTicket` also uses the same `message_seq` counter.

### Generic DTLS Finished Send Path Resets the Counter

`D:\project\wolfssl-master\src\internal.c:25220`

```c
#ifdef WOLFSSL_DTLS
if ((!ssl->options.resuming &&
        ssl->options.side == WOLFSSL_SERVER_END) ||
    (ssl->options.resuming &&
        ssl->options.side == WOLFSSL_CLIENT_END)) {
    ssl->keys.dtls_handshake_number = 0;
    ssl->keys.dtls_expected_peer_handshake_number = 0;
}
#endif
```

This reset is under `WOLFSSL_DTLS`, not under a DTLS 1.2-only condition. No guard such as `!IsAtLeastTLSv1_3(...)` was found around this reset.

### Generic DTLS Finished Receive Path Also Resets the Counter

`D:\project\wolfssl-master\src\internal.c:18102`

```c
#ifdef WOLFSSL_DTLS
if (ssl->options.dtls) {
    if ((!ssl->options.resuming && ssl->options.side == WOLFSSL_CLIENT_END) ||
         (ssl->options.resuming && ssl->options.side == WOLFSSL_SERVER_END)){
        DtlsMsgPoolReset(ssl);
        ssl->keys.dtls_handshake_number = 0;
        ssl->keys.dtls_expected_peer_handshake_number = 0;
    }
}
#endif
```

This is the second reset path. It also does not exclude DTLS 1.3.

## Existing wolfSSL Test Coverage

wolfSSL has DTLS 1.3 tests that inspect `message_seq` for ClientHello retransmission/fragmentation paths:

`D:\project\wolfssl-master\tests\api\test_dtls.c:1841`

```c
static int test_dtls13_get_message_seq(const char* msg, int msgSz,
    word16* msgSeq)
```

One test explicitly checks that a retransmitted CH1 keeps its original handshake `message_seq` while the DTLS record sequence changes:

```c
/* The handshake message_seq remains the original CH1 value; only the DTLS record
 * sequence is moved past the fragmented CH2 flight */
```

However, no direct test was found that asserts `NewSessionTicket` or `KeyUpdate` sent after handshake completion uses a non-reset `message_seq`. No direct string evidence such as `NewSessionTicket message_seq`, `KeyUpdate message_seq`, or `post-handshake message_seq` exists in the audited DTLS tests.

## Runtime Evidence

Compiled source-behavior harness:

`D:\project\SpecTrace\test-wolfssl-dtls\rfc9147\101-150\repro_message_seq_139_source_check.c`

Observed result:

```text
Conclusion: PASS - source behavior confirms ID 139 as a real partial/likely mismatch: DTLS 1.3 post-handshake messages use dtls_handshake_number, but generic DTLS Finished paths reset that counter to zero and no direct post-handshake message_seq continuity test was found.
```

Selected assertions:

```text
PASS DTLS 1.3 handshake header uses dtls_handshake_number                 contains "c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);"
PASS KeyUpdate sends through Dtls13HandshakeSend                          contains "Dtls13HandshakeSend(ssl, output"
PASS NewSessionTicket sends through Dtls13HandshakeSend                   contains "Dtls13HandshakeSend(ssl, output"
PASS SendFinished resets DTLS handshake number                            contains "ssl->keys.dtls_handshake_number = 0;"
PASS DoFinished resets DTLS handshake number                              contains "ssl->keys.dtls_handshake_number = 0;"
PASS no direct post-handshake message_seq continuity test                 does not contain "post-handshake message_seq"
PASS no NewSessionTicket message_seq assertion                            does not contain "NewSessionTicket message_seq"
PASS no KeyUpdate message_seq assertion                                   does not contain "KeyUpdate message_seq"
```

This is a compiled and executed source-behavior check. It does not claim packet-level wire capture of a post-handshake `NewSessionTicket` or `KeyUpdate`; it verifies the source paths that generate those messages and the reset paths that affect their `message_seq`.

## Inconsistency Reason

Implemented behavior:

| Area                                                                                   | wolfSSL behavior                                    |
| -------------------------------------------------------------------------------------- | --------------------------------------------------- |
| DTLS 1.3 handshake header has `message_seq`                                          | Implemented.                                        |
| New DTLS 1.3 handshake sends increment the counter                                     | Implemented in `Dtls13HandshakeSend`.             |
| Retransmission can reuse buffered data                                                 | Implemented through DTLS 1.3 RTX record structures. |
| Post-handshake `NewSessionTicket` and `KeyUpdate` use DTLS 1.3 handshake send path | Implemented.                                        |

Problematic behavior:

| RFC 9147 requirement                                                                                             | wolfSSL audited behavior                                                                                                                                       |
| ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| DTLS 1.3 `message_seq` is not reset for post-handshake messages.                                               | Generic DTLS `Finished` send/receive paths reset `ssl->keys.dtls_handshake_number` to zero after the main handshake.                                       |
| A new post-handshake message must be distinguishable from a retransmission of an earlier post-handshake message. | If the counter was reset, the first post-handshake message can reuse `message_seq = 0`, weakening that distinction.                                          |
| Direct regression coverage should prove this behavior.                                                           | Existing tests cover ClientHello retransmission `message_seq`, but no direct post-handshake `NewSessionTicket`/`KeyUpdate` sequence assertion was found. |

The root cause appears to be shared DTLS 1.2-era counter reset logic being used in DTLS 1.3 paths without excluding DTLS 1.3 post-handshake semantics.

## Impact

Peers that rely on RFC 9147 post-handshake reliability semantics may misclassify a newly generated post-handshake message as an old retransmission if `message_seq` restarts at zero after the main handshake. This is most relevant for `NewSessionTicket` and `KeyUpdate`, which are implemented post-handshake messages in wolfSSL. It may affect ACK/retransmission state and post-handshake message ordering under loss or duplicate delivery.

## Suggested Fix Direction

1. Guard the generic DTLS Finished reset so it only applies to DTLS versions before 1.3.
2. Keep `ssl->keys.dtls_handshake_number` continuous for DTLS 1.3 after the main handshake.
3. Add packet-level tests that complete a DTLS 1.3 handshake, then capture post-handshake `NewSessionTicket` and `KeyUpdate` records and assert their `message_seq` values continue from the main handshake rather than returning to zero.
4. Add retransmission tests for post-handshake messages to confirm retransmitted records reuse the old `message_seq` while newly generated post-handshake messages increment it.
