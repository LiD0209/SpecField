# Pre-DTLS 1.3 Cached Legacy Session ID Handling Is Not Proven

## Summary
This item is confirmed as partially satisfied. wolfSSL implements the main related DTLS 1.3 path, but this audit could not prove the full conditional behavior required by the extracted RFC 9147 rule.

## Standard Requirement
Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: RFC 9147 Section 5.3, ClientHello Format; Section 5.2.1, Denial-of-Service Countermeasures

Original English normative text:

```text
A client which has a cached session ID set by a pre-DTLS 1.3 server SHOULD set this field to that value.
```

Extracted requirement:

```text
Condition: client has a cached session ID set by a pre-DTLS 1.3 server
Action: set to cached value
```

## Relevant Source Code
- `src/tls13.c:4503`
- `src/tls13.c:7707`
- `src/tls13.c:7676`
- `src/tls13.c:7677`
- `src/tls13.c:4824`
- `src/tls13.c:4825`

```c
// src/tls13.c:4503
4500:        }
4501:        else {
4502:            /* Invalid session ID length. Reset it. */
4503:            ssl->session->sessionIDSz = 0;
4504:            if (output != NULL)
4505:                output[*idx] = 0;
4506:            (*idx)++;

// src/tls13.c:7707
7704:    if (ssl->options.dtls) {
7705:        /* RFC 9147 Section 5.3: DTLS 1.3 ServerHello must have empty
7706:         * legacy_session_id_echo. */
7707:        output[idx++] = 0;
7708:    }
7709:    else
7710:#endif

// src/tls13.c:7676
7673:    AddTls13Headers(output, length, server_hello, ssl);
7674:
7675:    /* The protocol version must be TLS v1.2 for middleboxes. */
7676:    output[idx++] = ssl->version.major;
7677:    output[idx++] = ssl->options.dtls ? DTLSv1_2_MINOR : TLSv1_2_MINOR;
7678:
7679:    if (extMsgType == server_hello) {
```

The snippets above show the concrete implementation branch used for this decision. The full line list remains in the comparison JSON for reproducibility.

## Implementation Behavior
通用 TLS 1.3 helper 能写入已有 session ID，但 DTLS 1.3 路径关闭 middlebox compat；未找到明确只在 pre-DTLS 1.3 cached session ID 时发送该值的专门策略。

## Inconsistency Reason
The implemented portion is visible in the cited source lines. The missing or unproven portion is: 通用 helper 可写 session ID，但 DTLS 1.3 特定条件策略证据不足。

## Runtime Evidence
Focused source assertion tests were run and saved in `source_assertion_tests.log`.

```text
source_assertions 验证 DTLS 1.3 服务端清空/不回显 session ID；未发现 pre-DTLS 1.3 cached session ID 专门策略。
```

Full handshake-level runtime testing was blocked because the current local CMake cache disables DTLS 1.3/CID and no linked wolfSSL runtime binary was available.

## Impact
The impact depends on the feature: peers using the covered base path interoperate, but deployments depending on the missing conditional policy may get weaker validation, configuration-dependent behavior, or lack of proof for edge cases.

## Fix Direction
Add explicit tests and, where needed, explicit implementation branches for the missing condition. Prefer protocol-level unit tests that construct the exact DTLS 1.3 message or record variant and assert the expected alert, discard, or state transition.
