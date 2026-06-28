# openHiTLS 在 ID 205 上的 `unsupported_certificate` 告警映射不一致说明

- date: 2026-04-18
- target: `openhitls-main/openhitls-main`
- related id: `205`
- related rule: `a certificate was of an unsupported type`

## 问题概述

RFC 8446 对证书相关告警有比较明确的语义区分：

- `bad_certificate`：证书损坏、签名校验失败等
- `unsupported_certificate`：证书类型不被支持

openHiTLS 当前实现中，确实存在 `ALERT_UNSUPPORTED_CERTIFICATE` 的发送路径；但并不是所有“证书类型不支持”或“证书能力不匹配”的错误都会稳定落到该告警。部分失败路径会被外层统一转换为 `ALERT_BAD_CERTIFICATE`。

因此，这里的不一致不是“没有实现 unsupported_certificate”，而是：

```text
对 unsupported type 的错误，告警映射不够稳定，部分路径会被泛化为 bad_certificate。
```

## 标准原文

标准文档位于 [TLS1.3.txt](/d:/project/conditionFuzzing/document/TLS1.3.txt:4925)。

`document/TLS1.3.txt` 第 4925-4935 行原文如下：

```text
bad_certificate:  A certificate was corrupt, contained signatures
   that did not verify correctly, etc.

unsupported_certificate:  A certificate was of an unsupported type.
```

这里的关键点是：

- `bad_certificate` 对应“证书损坏/签名失败/格式异常等更泛化的错误”
- `unsupported_certificate` 对应“证书类型不支持”这一更具体的语义

因此，若我们讨论的是“unsupported type”，理论上更精确的告警应为 `unsupported_certificate`。

## openHiTLS 相关代码说明

### 1. 某些错误码会被映射为 `ALERT_UNSUPPORTED_CERTIFICATE`

在 [recv_certificate.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/recv/src/recv_certificate.c:37) 中，PKI 错误到告警的映射表包含：

```c
{HITLS_X509_ERR_PROCESS_CRITICALEXT, ALERT_UNSUPPORTED_CERTIFICATE},
{HITLS_X509_ERR_CERT_INVALID_PUBKEY, ALERT_UNSUPPORTED_CERTIFICATE},
```

这说明 openHiTLS 并不是完全没有实现 `unsupported_certificate`。

另外，在密钥用途检查失败时，也会直接发送该告警：

```c
if (... && !CheckCertKeyUsage(ctx, peerCert)) {
    ...
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_UNSUPPORTED_CERTIFICATE);
    ...
}
```

对应位置见 [recv_certificate.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/recv/src/recv_certificate.c:248)。

### 2. 但证书类型检查失败并不总是落到 `unsupported_certificate`

在 [hs_cert.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/common/src/hs_cert.c:48) 中：

```c
static int32_t CheckCertType(CERT_Type expectCertType, HITLS_CERT_KeyType checkedKeyType)
{
    ...
    if (expectCertType != checkedCertType) {
        ...
        return HITLS_MSG_HANDLE_UNSUPPORT_CERT;
    }
    return HITLS_SUCCESS;
}
```

这说明：

- openHiTLS 在底层确实能识别“证书类型不匹配/不支持”
- 也有专门的错误码 `HITLS_MSG_HANDLE_UNSUPPORT_CERT`

### 3. 但外层处理时，会统一发送 `ALERT_BAD_CERTIFICATE`

在 [recv_certificate.c](/d:/project/conditionFuzzing/openhitls-main/openhitls-main/tls/handshake/recv/src/recv_certificate.c:257) 中：

```c
if (ctx->isClient) {
    ret = ClientCheckCert(ctx, peerCert);
} else {
    ret = ServerCheckCert(ctx, peerCert);
}
if (ret != HITLS_SUCCESS) {
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_BAD_CERTIFICATE);
    ...
    return ret;
}
```

也就是说：

- 即使底层 `CheckCertType()` 识别出了“不支持的证书类型”
- 只要错误沿着 `ClientCheckCert/ServerCheckCert -> ProcessPeerCertificate` 这条路径返回
- 最终外层也可能统一发成 `ALERT_BAD_CERTIFICATE`

## 不一致原因

这个不一致的核心原因是：

- RFC 8446 对 `unsupported_certificate` 和 `bad_certificate` 做了语义区分
- openHiTLS 内部虽然有一部分分支保留了这种区分
- 但另一部分更通用的证书检查失败路径，在外层被统一收敛成 `ALERT_BAD_CERTIFICATE`

更准确地说，ID 205 的不一致是：

```text
标准语义：certificate was of an unsupported type -> unsupported_certificate
openHiTLS 实现：部分路径确实发送 unsupported_certificate，但部分“类型不支持/能力不匹配”错误会被统一映射为 bad_certificate
```

## 为什么它不是“完全不满足”

因为 openHiTLS 仍然具备以下能力：

- 定义了 `ALERT_UNSUPPORTED_CERTIFICATE`
- 在某些明确的证书能力检查失败路径上会发送该告警
- 能识别与证书类型/用途/公钥能力相关的错误

因此它不是“完全没实现”，而是“实现了，但映射粒度不够稳定”。

## 结论

因此，ID 205 更适合归类为：

- 证书告警映射粒度差异
- 部分满足

而不是简单写成：

- 满足

因为“unsupported type”这一语义在 openHiTLS 中并没有稳定、一致地落到 `unsupported_certificate`，仍存在被泛化为 `bad_certificate` 的实现路径。
