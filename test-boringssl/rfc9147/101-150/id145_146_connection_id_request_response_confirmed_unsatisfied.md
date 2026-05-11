# DTLS Connection ID request response messages are not implemented

## Summary
BoringSSL 的 DTLS 1.3 record layer 明确不协商、不发送 CID，并拒绝带 CID bit 的记录。没有 CID post-handshake message 解析、发送、请求计数或 excessive request 处理。

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section: RFC 9147 Section 9, Connection ID Updates

```text
Endpoints SHOULD respond to RequestConnectionId by sending a NewConnectionId with usage "cid_spare" containing num_cids CIDs as soon as possible.
```

在协商 connection_id 后，端点应能处理 RequestConnectionId，并用 NewConnectionId 返回请求数量的 spare CIDs；过量请求可少返回或不返回。

## Relevant Source Code
`ssl/dtls_record.cc:170`

```c
if (out->type & 0x10) {
  // Connection ID bit set, which we didn't negotiate.
  return false;
}
```

`ssl/dtls_record.cc:431`

```c
// The DTLS 1.3 has a variable length record header. We never send Connection
// ID, we always send 16-bit sequence numbers, and we send a length.
```

`ssl/dtls_record.cc:533`

```c
// We set C=0 (no Connection ID), S=1 (16-bit sequence number), L=1
out[0] = 0x2c | (epoch & 0x3);
```

源码搜索未发现 `RequestConnectionId`、`NewConnectionId`、`cid_spare`、`num_cids` 或 RFC 9146 connection_id 状态机。

## Implementation Behavior
BoringSSL 的 DTLS 1.3 record layer 明确不协商、不发送 CID，并拒绝带 CID bit 的记录。没有 CID post-handshake message 解析、发送、请求计数或 excessive request 处理。

## Inconsistency Reason
标准中的 CID 更新要求以已协商 CID 为条件。实现没有该功能面，因此无法满足 RequestConnectionId 到 NewConnectionId 的响应语义，也无法实现返回少于 `num_cids` 的过量请求策略。

## Runtime Evidence
Focused test source: `phase2_dtls13_static_runtime_checks.py`

Focused test log: `phase2_dtls13_static_runtime_checks.log`

The test confirms the static code predicates for this finding. Full BoringSSL runner execution was blocked because this workspace has no `cmake`, `ninja`, `go`, or `bazel` in PATH and no prebuilt `ssl_test.exe` or `bssl_shim.exe` was found.

## Impact
应用需要 DTLS 1.3 Connection ID 和路径迁移/多路径隐私能力时，BoringSSL 不能提供 RFC 9147 Section 9 的互操作行为。

## Fix Direction
实现 RFC 9146 connection_id 扩展协商、record header CID 编解码、NewConnectionId/RequestConnectionId post-handshake state machines、outstanding-request 限制和 unexpected_message/too_many_cids_requested 错误处理。
