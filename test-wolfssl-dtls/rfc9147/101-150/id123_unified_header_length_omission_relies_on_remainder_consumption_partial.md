# Unified Header Length Omission Relies On Remainder Consumption

## Summary
This item is confirmed as partially satisfied. wolfSSL implements the main related DTLS 1.3 path, but this audit could not prove the full conditional behavior required by the extracted RFC 9147 rule.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 4.1, The DTLS Record Layer; Section 4.2.1, DTLSCiphertext; Section 4.2.2, Record Header

Original English normative text:

```text
Omitting the length field MUST only be used for the last record in a datagram.
```

Extracted requirement:

```text
Condition: when omitting the length field
Action: must only be used for the last record in a datagram
```

## Relevant Source Code
- `src/dtls13.c:111`
- `src/dtls13.c:1268`
- `src/dtls13.c:1273`
- `src/dtls13.c:1537`
- `src/dtls13.c:1555`
- `src/dtls13.c:1546`
- `src/dtls13.c:1564`
- `src/internal.c:12071`

```c
// src/dtls13.c:111
108:   can dynamically choose to remove the length from the header to save
109:   space. Also it will need to account for client connection ID when
110:   supported. */
111:#define DTLS13_UNIFIED_HEADER_SIZE 5
112:#define DTLS13_MIN_CIPHERTEXT 16
113:#ifndef DTLS13_MIN_RTX_INTERVAL
114:#define DTLS13_MIN_RTX_INTERVAL (DTLS_TIMEOUT_INIT * 1000)

// src/dtls13.c:1268
1265:    /* include 16-bit seq */
1266:    *flags |= DTLS13_SEQ_LEN_BIT;
1267:    /* include 16-bit length */
1268:    *flags |= DTLS13_LEN_BIT;
1269:
1270:    seqNumber = (word16)w64GetLow32(ssl->dtls13EncryptEpoch->nextSeqNumber);
1271:    c16toa(seqNumber, out + idx);

// src/dtls13.c:1273
1270:    seqNumber = (word16)w64GetLow32(ssl->dtls13EncryptEpoch->nextSeqNumber);
1271:    c16toa(seqNumber, out + idx);
1272:    idx += OPAQUE16_LEN;
1273:    c16toa(length, out + idx);
1274:
1275:    return 0;
1276:}
```

The snippets above show the concrete implementation branch used for this decision. The full line list remains in the comparison JSON for reproducibility.

## Implementation Behavior
解析端在 L bit 清除时把剩余 datagram 作为当前记录，但没有独立证明该无长度格式只出现在 datagram 最后一个记录。

## Inconsistency Reason
The implemented portion is visible in the cited source lines. The missing or unproven portion is: 实现不会发送违规中间无长度记录，接收端语义上把无 length 解释为最后记录，但缺少显式错误路径。

## Runtime Evidence
Focused source assertion tests were run and saved in `source_assertion_tests.log`.

```text
source_assertions 中 unified_header_length_bit_parse 通过：L bit 清除时消费剩余 datagram；发送端始终设置 L bit。
```

Full handshake-level runtime testing was blocked because the current local CMake cache disables DTLS 1.3/CID and no linked wolfSSL runtime binary was available.

## Impact
The impact depends on the feature: peers using the covered base path interoperate, but deployments depending on the missing conditional policy may get weaker validation, configuration-dependent behavior, or lack of proof for edge cases.

## Fix Direction
Add explicit tests and, where needed, explicit implementation branches for the missing condition. Prefer protocol-level unit tests that construct the exact DTLS 1.3 message or record variant and assert the expected alert, discard, or state transition.
