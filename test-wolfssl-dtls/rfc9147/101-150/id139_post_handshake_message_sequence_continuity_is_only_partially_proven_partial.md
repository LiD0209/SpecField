# Post-Handshake Message Sequence Continuity Is Only Partially Proven

## Summary
This item is confirmed as partially satisfied. wolfSSL implements the main related DTLS 1.3 path, but this audit could not prove the full conditional behavior required by the extracted RFC 9147 rule.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 5.5, Handshake Message Format and Reordering

Original English normative text:

```text
However, in DTLS 1.3 the message_seq is not reset, to allow distinguishing a retransmission from a previously sent post-handshake message from a newly sent post-handshake message.
```

Extracted requirement:

```text
Condition: post-handshake message exchange in DTLS 1.3
Action: must not be reset
```

## Relevant Source Code
- `src/dtls13.c:202`
- `src/dtls13.c:367`
- `src/dtls13.c:339`
- `src/dtls13.c:827`
- `src/dtls13.c:952`
- `src/internal.c:10900`
- `src/internal.c:19586`

```c
// src/dtls13.c:202
199:
200:    hdr->msg_type = msg_type;
201:    c32to24((word32)msg_length, hdr->length);
202:    c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);
203:
204:    c32to24(frag_offset, hdr->fragmentOffset);
205:    c32to24(frag_length, hdr->fragmentLength);

// src/dtls13.c:367
364:        idx = 0;
365:
366:        /* message not in order */
367:        if (ssl->keys.dtls_expected_peer_handshake_number != msg->seq)
368:            break;
369:
370:        /* message not complete */

// src/dtls13.c:339
336:static void Dtls13MsgWasProcessed(WOLFSSL* ssl, enum HandShakeType hs)
337:{
338:    if (ssl->options.dtlsStateful)
339:        ssl->keys.dtls_expected_peer_handshake_number++;
340:
341:#ifdef WOLFSSL_RW_THREADED
342:    if (wc_LockMutex(&ssl->dtls13Rtx.mutex) == 0)
```

The snippets above show the concrete implementation branch used for this decision. The full line list remains in the comparison JSON for reproducibility.

## Implementation Behavior
代码中 post-handshake ACK/KeyUpdate 使用同一 DTLS 1.3 RTX/sequence 结构，但未能证明所有 post-handshake 消息永不重置 message_seq。

## Inconsistency Reason
The implemented portion is visible in the cited source lines. The missing or unproven portion is: 同一序列状态贯穿 DTLS 1.3 路径，但缺少完整 post-handshake 覆盖测试。

## Runtime Evidence
Focused source assertion tests were run and saved in `source_assertion_tests.log`.

```text
source_assertions 验证 KeyUpdate/ACK 使用 DTLS 1.3 RTX/sequence 结构，但未能源码证明所有 post-handshake 不重置。
```

Full handshake-level runtime testing was blocked because the current local CMake cache disables DTLS 1.3/CID and no linked wolfSSL runtime binary was available.

## Impact
The impact depends on the feature: peers using the covered base path interoperate, but deployments depending on the missing conditional policy may get weaker validation, configuration-dependent behavior, or lack of proof for edge cases.

## Fix Direction
Add explicit tests and, where needed, explicit implementation branches for the missing condition. Prefer protocol-level unit tests that construct the exact DTLS 1.3 message or record variant and assert the expected alert, discard, or state transition.
