# CID peer address update lacks a strict newer sequence-number gate

## Summary
本项复核结论为 `confirmed_partial`。

RFC 9146 Section 6 要求：CID 保护的 DTLS 连接在替换 peer address 前，触发替换的 datagram 必须已经通过密码学验证，并且必须比已经收到的最新 datagram 更新；这里的 “newer” 同时包含 epoch 和 sequence number。

wolfSSL 在 pending-peer 路径中实现了重要的一部分保护：只有记录成功去保护后才会把 `pendingPeer` 提升为当前 peer。但提升点没有再检查触发记录的 sequence number 是否比 “newest datagram received” 更新。普通 DTLS 1.2 replay window 可以接受窗口内的旧序号记录，也可以接受上一 epoch 窗口内的记录；这些记录可以是有效 DTLS 记录，但不一定有资格触发地址更新。

范围说明：该问题适用于启用 DTLS CID，且应用使用 `wolfSSL_dtls_set_pending_peer()` 做地址迁移的路径。它不是在声称 wolfSSL 默认 socket receive 路径会无条件接受任意源地址变化。

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9146#section-6

Section: RFC 9146 Section 6, Peer Address Update

```text
The received datagram is "newer" (in terms of both epoch and sequence number)
than the newest datagram received.
```

这一条件属于 MUST 级别约束。RFC 9146 Section 6 的前置语义是 receiver **MUST NOT** replace the address unless the listed conditions are met；因此只有同时满足密码学验证、newer datagram、以及新地址可接收/处理记录的策略要求时，才允许替换 peer address。

这里的 newer 条件不同于普通 anti-replay window。普通 replay window 决定一条记录是否可以作为 DTLS 记录被接受；RFC 9146 的 newer 条件额外决定该记录是否可以触发 peer address update。

## Relevant Source Code
`wolfssl-master/src/ssl.c:1459`

```c
int wolfSSL_dtls_set_pending_peer(WOLFSSL* ssl, void* peer, unsigned int peerSz)
{
    ...
    else {
        ret = SockAddrSet(&ssl->buffers.dtlsCtx.pendingPeer, peer, peerSz,
                ssl->heap);
    }
    if (ret == WOLFSSL_SUCCESS)
        ssl->buffers.dtlsCtx.processingPendingRecord = 0;
    ...
}
```

`wolfssl-master/src/internal.c:22584`

```c
static void dtlsProcessPendingPeer(WOLFSSL* ssl, int deprotected)
{
    if (ssl->buffers.dtlsCtx.pendingPeer.sa != NULL) {
        if (!deprotected) {
            ...
        }
        else {
            /* Pending peer present and record deprotected. Update the peer. */
            (void)wolfSSL_dtls_set_peer(ssl,
                    ssl->buffers.dtlsCtx.pendingPeer.sa,
                    ssl->buffers.dtlsCtx.pendingPeer.sz);
            ssl->buffers.dtlsCtx.processingPendingRecord = 0;
            dtlsClearPeer(&ssl->buffers.dtlsCtx.pendingPeer);
        }
    }
    ...
}
```

`wolfssl-master/src/internal.c:23283`

```c
if (IsDtlsNotSctpMode(ssl)) {
    DtlsUpdateWindow(ssl);
}
#ifdef WOLFSSL_DTLS_CID
/* Update the peer if we were able to de-protect the message */
if (IsEncryptionOn(ssl, 0))
    dtlsProcessPendingPeer(ssl, 1);
#endif
```

`wolfssl-master/src/internal.c:19034`

```c
if (ssl->keys.curEpoch == peerSeq->nextEpoch) {
    next_hi = peerSeq->nextSeq_hi;
    next_lo = peerSeq->nextSeq_lo;
    window = peerSeq->window;
}
else if (ssl->keys.curEpoch == peerSeq->nextEpoch - 1) {
    next_hi = peerSeq->prevSeq_hi;
    next_lo = peerSeq->prevSeq_lo;
    window = peerSeq->prevWindow;
}
else {
    return 0;
}
```

`wolfssl-master/src/internal.c:19082`

```c
else if (curLT) {
    ...
    if (window[idx] & (1 << newDiff)) {
        WOLFSSL_MSG("Current record sequence number already received.");
        return 0;
    }
}
```

## Implementation Behavior
`wolfSSL_dtls_set_pending_peer()` 保存候选 peer address 到 `ssl->buffers.dtlsCtx.pendingPeer`。

记录处理开始后，`dtlsProcessPendingPeer(ssl, 0)` 用 `processingPendingRecord` 跟踪下一条加密记录。记录成功解密和认证后，DTLS CID 路径调用 `dtlsProcessPendingPeer(ssl, 1)`，该函数直接通过 `wolfSSL_dtls_set_peer()` 提升 `pendingPeer`。

提升点没有保存或比较触发记录的 sequence number 与 “newest datagram received” 的 sequence number。它依赖普通 DTLS 记录接收路径，而普通 replay-window 逻辑允许窗口内尚未收到的旧序号记录通过；在 DTLS 1.2 中，该逻辑还保留了 previous-epoch window。

## Inconsistency Reason
RFC 9146 要求 peer address update 必须由一个比已接收最新 datagram 更新的 datagram 触发，并明确把 sequence number 纳入 newer 判断。

wolfSSL 已满足密码学验证门控：只有记录成功去保护后才提升 pending peer。缺失的是地址更新专用的 strict newer sequence-number gate。窗口内旧 sequence number 的记录可能仍是有效 DTLS 记录，但它不一定比最新 datagram 更新，因此不应仅凭 replay-window 接受结果触发地址替换。

因此该项不是完全不满足，而是部分满足：记录认证条件存在，CID 匹配路径存在，但 pending-peer promotion 没有独立执行 RFC 9146 要求的 newest-datagram sequence-number 比较。

## Static Evidence
Verification script: `test-wolfssl-dtls/rfc9146/001-022/verify_wolfssl_dtls_cid_001_022.py`

Verification log: `test-wolfssl-dtls/rfc9146/001-022/verify_wolfssl_dtls_cid_001_022.log`

相关检查结果：

```text
PASS previous epoch accepted: DTLS 1.2 window logic accepts previous epoch window
PASS pending peer function found: dtlsProcessPendingPeer is present
PASS peer update after deprotect: pending peer is promoted after deprotection
PASS no strict newer gate: peer promotion body has no explicit newest-datagram comparison
```

这些检查证明了源码中同时存在 previous-epoch/window 接收逻辑和无 newest-datagram 比较的 peer promotion 路径。它们是静态验证证据，不等同于完整网络端到端复现。

## Impact
在启用 DTLS CID 并使用 `wolfSSL_dtls_set_pending_peer()` 处理地址迁移的部署中，一个已通过认证但不是最新的记录可能触发 pending peer 提升。这会使重排记录或 previous-epoch 窗口内记录具备 RFC 9146 不希望赋予它们的地址更新能力。

实际可达性取决于应用如何检测源地址变化、何时调用 `wolfSSL_dtls_set_pending_peer()`，以及构建配置是否启用了 DTLS CID。

## Fix Direction
为 CID peer address update 路径维护独立的 “newest datagram received” 状态，至少包含 epoch 和 sequence number。

在 `dtlsProcessPendingPeer(ssl, 1)` 提升 `pendingPeer` 前，将当前触发记录的 epoch/sequence number 与该 newest-datagram 状态比较。只有记录已成功去保护，并且在 RFC 9146 意义上严格更新时，才调用 `wolfSSL_dtls_set_peer()` 替换 peer address。

普通 replay-window 逻辑仍可继续决定记录是否作为 DTLS 记录被接受；新增 gate 只应限制该记录是否允许触发 peer address replacement。
