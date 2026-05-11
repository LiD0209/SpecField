# DTLS 1.3 legacy_cookie nonzero validation is missing

## Summary
BoringSSL 客户端会在初始 DTLS ClientHello 中写入当前 `hs->dtls_cookie`，初始状态为空；但服务端解析任意 DTLS ClientHello cookie 后未在 DTLS 1.3 路径中执行非零检查。

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9147

Section: RFC 9147 Section 5.3, ClientHello Message

```text
A DTLS 1.3-only client MUST set the legacy_cookie field to zero length. If a DTLS 1.3 ClientHello is received with any other value in this field, the server MUST abort the handshake with an "illegal_parameter" alert.
```

标准要求 DTLS 1.3 ClientHello 的 legacy_cookie 字段为空；服务端收到非空值时必须中止握手并使用 illegal_parameter。

## Relevant Source Code
`ssl/extensions.cc:138`

```c
if (SSL_is_dtls(out->ssl)) {
  CBS cookie;
  if (!CBS_get_u8_length_prefixed(cbs, &cookie)) {
    OPENSSL_PUT_ERROR(SSL, SSL_R_CLIENTHELLO_PARSE_FAILED);
    return false;
  }
  out->dtls_cookie = CBS_data(&cookie);
  out->dtls_cookie_len = CBS_len(&cookie);
}
```

`ssl/handshake_server.cc:658`

```c
if (!ssl_parse_clienthello_tlsext(hs, &client_hello)) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_PARSE_TLSEXT);
  return ssl_hs_error;
}
```

解析代码保留 legacy_cookie 指针和长度，但服务端 DTLS 1.3 路径没有对 `client_hello.dtls_cookie_len` 做非零拒绝。

## Implementation Behavior
BoringSSL 客户端会在初始 DTLS ClientHello 中写入当前 `hs->dtls_cookie`，初始状态为空；但服务端解析任意 DTLS ClientHello cookie 后未在 DTLS 1.3 路径中执行非零检查。

## Inconsistency Reason
标准要求服务端对非零 legacy_cookie 执行强制拒绝。实现只完成字段解析和客户端空字段生成，没有服务端非法值检查，也没有将该情况映射为 `illegal_parameter`。

## Runtime Evidence
Focused test source: `phase2_dtls13_static_runtime_checks.py`

Focused test log: `phase2_dtls13_static_runtime_checks.log`

The test confirms the static code predicates for this finding. Full BoringSSL runner execution was blocked because this workspace has no `cmake`, `ninja`, `go`, or `bazel` in PATH and no prebuilt `ssl_test.exe` or `bssl_shim.exe` was found.

## Impact
非标准客户端可以在 DTLS 1.3 ClientHello 中携带 legacy_cookie 而不被该专门规则拒绝，导致协议严格符合性缺口。

## Fix Direction
在 DTLS 1.3 ServerHello 前的 ClientHello 处理路径中加入 `client_hello.dtls_cookie_len != 0` 检查，并发送 fatal `illegal_parameter` alert。保留 DTLS 1.2 HelloVerifyRequest cookie 路径。
