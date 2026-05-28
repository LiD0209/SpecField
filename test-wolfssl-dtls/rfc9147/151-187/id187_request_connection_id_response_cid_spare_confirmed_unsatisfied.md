# RequestConnectionId response with cid_spare is not implemented

## Summary

This is a confirmed unsatisfied DTLS 1.3 compliance finding in wolfSSL. The requested repository name was `wolfssl-main`, but the available audited tree is `wolfssl-master`.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section: RFC 9147 Section 9 Connection IDs

```text
When responding to RequestConnectionId, the sender supplies a NewConnectionId with usage set to cid_spare.
```

该要求需要实现具体的 DTLS 1.3 状态或消息语义，而不是仅有常量或旧版 CID 扩展支持。

## Relevant Source Code

```c
wolfssl/internal.h:3793
WOLFSSL_LOCAL void TLSX_ConnectionID_Free(byte* ext, void* heap);
WOLFSSL_LOCAL word16 TLSX_ConnectionID_Write(byte* ext, byte* output);
WOLFSSL_LOCAL int TLSX_ConnectionID_Parse(WOLFSSL* ssl, const byte* input,

src/internal.c:38422
if (ssl->options.useDtlsCID)
    DtlsCIDOnExtensionsParsed(ssl);
```

相关代码只展示了已存在的 close_notify 或 CID 扩展/统一头处理路径。

## Implementation Behavior

wolfSSL exposes RFC 9146-style Connection ID APIs and unified-header CID parsing, but repository-wide scans find no NewConnectionId, RequestConnectionId, cid_spare, or cid_immediate implementation.

## Inconsistency Reason

标准要求：RFC 9147 Section 9 defines NewConnectionId and RequestConnectionId messages and the usage values cid_spare and cid_immediate for dynamic CID rotation.

实现行为：wolfSSL exposes RFC 9146-style Connection ID APIs and unified-header CID parsing, but repository-wide scans find no NewConnectionId, RequestConnectionId, cid_spare, or cid_immediate implementation.

不一致原因：The required protocol messages and usage semantics are absent; existing CID support only covers negotiated CID extension/header processing.

## Runtime Evidence

Focused verification script: `verify_wolfssl_dtls13_151_187.ps1`

Log: `verify_wolfssl_dtls13_151_187.log`

The script passed under `powershell -NoProfile -ExecutionPolicy Bypass`. It records that `WOLFSSL_DTLS13:BOOL=no` and `WOLFSSL_DTLS_CID:BOOL=no` in the local CMake cache. For dynamic CID findings it also records `ABSENT NewConnectionId`, `ABSENT RequestConnectionId`, `ABSENT cid_immediate`, and `ABSENT cid_spare`.

## Impact

Peers relying on this DTLS 1.3 behavior cannot obtain the exact RFC 9147 semantics from this implementation path. For dynamic CID, runtime CID rotation messages are unavailable. For close_notify, generic shutdown works, but the DTLS 1.3 post-close packet ordering rule is not proven.

## Fix Direction

Implement the missing DTLS 1.3 state machine behavior and add focused tests. For dynamic CID this means adding NewConnectionId/RequestConnectionId parsing, serialization, usage validation, and CID activation timing. For close_notify this means storing the valid closure alert RecordNumber and ignoring later data with a greater epoch/sequence pair.
