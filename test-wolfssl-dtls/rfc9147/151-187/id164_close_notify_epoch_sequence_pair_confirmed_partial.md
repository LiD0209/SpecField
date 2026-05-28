# DTLS 1.3 close_notify lacks epoch/sequence pair gating

## Summary

This is a confirmed partial DTLS 1.3 compliance finding in wolfSSL. The requested repository name was `wolfssl-main`, but the available audited tree is `wolfssl-master`.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section: RFC 9147 Section 5.10 Closure Alerts

```text
After a valid closure alert is received, any received data with an epoch/sequence number pair after that of the closure alert MUST be ignored.
```

该要求需要实现具体的 DTLS 1.3 状态或消息语义，而不是仅有常量或旧版 CID 扩展支持。

## Relevant Source Code

```c
src/internal.c:22226
if (*type == close_notify) {
    ssl->options.closeNotify = 1;
}

src/internal.c:23664
if (type == close_notify) {
    ssl->buffers.inputBuffer.idx = ssl->buffers.inputBuffer.length;
    ssl->options.processReply = doProcessInit;
    return ssl->error = ZERO_RETURN;
}
```

相关代码只展示了已存在的 close_notify 或 CID 扩展/统一头处理路径。

## Implementation Behavior

DoAlert records alert_history and sets closeNotify, and ProcessReply returns ZERO_RETURN on close_notify, but no source path stores close_notify curEpoch64/curSeq or compares later records against that saved pair.

## Inconsistency Reason

标准要求：RFC 9147 Section 5.10 requires implementations to remember the epoch/sequence number pair of a valid received closure alert and ignore later data whose pair is after that alert.

实现行为：DoAlert records alert_history and sets closeNotify, and ProcessReply returns ZERO_RETURN on close_notify, but no source path stores close_notify curEpoch64/curSeq or compares later records against that saved pair.

不一致原因：Generic closure handling exists, but the DTLS 1.3 pair-based ignore requirement is not implemented or exposed in the inspected paths.

## Runtime Evidence

Focused verification script: `verify_wolfssl_dtls13_151_187.ps1`

Log: `verify_wolfssl_dtls13_151_187.log`

The script passed under `powershell -NoProfile -ExecutionPolicy Bypass`. It records that `WOLFSSL_DTLS13:BOOL=no` and `WOLFSSL_DTLS_CID:BOOL=no` in the local CMake cache. For dynamic CID findings it also records `ABSENT NewConnectionId`, `ABSENT RequestConnectionId`, `ABSENT cid_immediate`, and `ABSENT cid_spare`.

## Impact

Peers relying on this DTLS 1.3 behavior cannot obtain the exact RFC 9147 semantics from this implementation path. For dynamic CID, runtime CID rotation messages are unavailable. For close_notify, generic shutdown works, but the DTLS 1.3 post-close packet ordering rule is not proven.

## Fix Direction

Implement the missing DTLS 1.3 state machine behavior and add focused tests. For dynamic CID this means adding NewConnectionId/RequestConnectionId parsing, serialization, usage validation, and CID activation timing. For close_notify this means storing the valid closure alert RecordNumber and ignoring later data with a greater epoch/sequence pair.
