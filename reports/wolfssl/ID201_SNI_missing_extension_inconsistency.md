# ID 201：SNI 缺失时 `missing_extension` 与 `handshake_failure` 的不一致

## 问题概述

`TLS 1.3` 标准对“服务器要求客户端发送 `server_name` 扩展，但客户端的 `ClientHello` 中缺失该扩展”给出了推荐的告警描述。  
`wolfSSL` 在对应路径上会中止握手，但发送的告警不是 `missing_extension`，而是 `handshake_failure`。

这构成的是“告警值与标准推荐不一致”，而不是“完全不拒绝该错误场景”。

## 标准原文

标准文件：[TLS1.3.txt](/d:/project/conditionFuzzing/document/TLS1.3.txt:5793)

原文如下：

```text
Servers MAY require clients to send a valid "server_name" extension.
Servers requiring this extension SHOULD respond to a ClientHello
lacking a "server_name" extension by terminating the connection with
a "missing_extension" alert.
```

### 标准含义

- 服务器可以要求客户端发送 `server_name` 扩展。
- 如果服务器要求了，而客户端没有发送，标准建议使用 `missing_extension` 告警终止连接。
- 这里使用的是 `SHOULD`，不是 `MUST`。

## wolfSSL 代码行为

关键代码在 [tls.c](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:2573)：

```c
if (ctx_sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) {
    sni = TLSX_SNI_Find(ssl_sni, ctx_sni->type);

    if (sni) {
        if (sni->status != WOLFSSL_SNI_NO_MATCH)
            continue;

        /* if ssl level overrides ctx level, it is ok. */
        if ((sni->options & WOLFSSL_SNI_ABORT_ON_ABSENCE) == 0)
            continue;
    }

    SendAlert(ssl, alert_fatal, handshake_failure);
    WOLFSSL_ERROR_VERBOSE(SNI_ABSENT_ERROR);
    return SNI_ABSENT_ERROR;
}
```

同一逻辑在 SSL 级别路径上再次出现，见 [tls.c](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:2592)。

### 代码含义

- 只有在启用 `WOLFSSL_SNI_ABORT_ON_ABSENCE` 时，`wolfSSL` 才会把“缺失 `server_name`”视为致命错误。
- 一旦进入该分支，代码直接执行：
  - `SendAlert(..., handshake_failure)`
  - 返回 `SNI_ABSENT_ERROR`

也就是说，这条路径发出去的告警就是 `handshake_failure`。


## 标准与代码对照

### 标准

- 条件：服务器要求 `server_name`
- 客户端行为：`ClientHello` 缺失 `server_name`
- 推荐告警：`missing_extension`

### wolfSSL

- 条件：启用 `WOLFSSL_SNI_ABORT_ON_ABSENCE`
- 客户端行为：`ClientHello` 缺失 `server_name`
- 实际告警：`handshake_failure`

## 不一致的原因

造成不一致的主要原因是：`wolfSSL` 对“缺失 SNI”采用了一个通用的“握手策略失败”处理分支，而不是使用 TLS 1.3 对扩展缺失更细粒度的 `missing_extension` 语义。

更具体地说：

- 该逻辑位于通用 SNI 处理代码中，而不是 TLS 1.3 专门的扩展缺失检查路径中。
- `wolfSSL` 把“要求 SNI 但客户端未提供”视为一种握手前提不满足，因此直接发送 `handshake_failure`。
- 标准对此场景给的是 `SHOULD use missing_extension`，而不是 `MUST use missing_extension`，因此这是“偏离推荐实现”，不是绝对的硬性违标。

## 结论

`wolfSSL` 在该场景下的行为是：

- 会拒绝缺失 `server_name` 的 `ClientHello`
- 但使用的是 `handshake_failure`
- 而不是标准推荐的 `missing_extension`

因此，这一项更准确地应归类为：

- 行为上部分符合标准意图
- 告警值与标准推荐不一致
- 属于建议项偏离，而非完全缺失校验
