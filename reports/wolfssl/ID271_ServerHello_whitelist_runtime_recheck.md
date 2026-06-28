# ID271 运行时复核：ServerHello 扩展白名单约束

## 总结

本次复核的结论是：wolfSSL 在当前构建下对 `ServerHello` 中的**额外未知扩展**没有执行严格拒绝。我们实际向客户端注入了带未知扩展 `0xFAFA` 的 `ServerHello`，结果没有触发立即失败，也没有发送 fatal alert，而是继续停在 `WANT_READ`。  

这说明 `ID271` 对应的 `ServerHello MUST only include ...` 没有被严格实现，因此该条维持“部分满足”是合理的，不应上调为“满足”。

## 1. 复核范围

本次复核针对 `201-300/compare_wolfssl_201_300.md` 中：

- `ID271`: `extensions must only include` `in ServerHello`

关注点是：

- 当 `ServerHello` 中出现**不在白名单中的额外未知扩展**时，wolfSSL 客户端是否会立即拒绝并中止握手。

## 2. RFC 8446 标准原文

标准文本来自：`document/TLS1.3.txt`

### 2.1 ServerHello 的白名单要求

`document/TLS1.3.txt:1743-1751`

> extensions: A list of extensions. The ServerHello MUST only include  
> extensions which are required to establish the cryptographic  
> context and negotiate the protocol version. All TLS 1.3  
> ServerHello messages MUST contain the "supported_versions"  
> extension. Current ServerHello messages additionally contain  
> either the "pre_shared_key" extension or the "key_share"  
> extension, or both (when using a PSK with (EC)DHE key  
> establishment). Other extensions (see Section 4.2) are sent  
> separately in the EncryptedExtensions message.

这段对应 `ID271`。标准语义很明确：TLS 1.3 的 `ServerHello` 是封闭白名单，不是开放扩展容器。

### 2.2 对未请求扩展响应的处理

`document/TLS1.3.txt:1988-1992`

> Implementations MUST NOT send extension responses if the remote  
> endpoint did not send the corresponding extension requests, with the  
> exception of the "cookie" extension in the HelloRetryRequest. Upon  
> receiving such an extension, an endpoint MUST abort the handshake  
> with an "unsupported_extension" alert.

这说明如果服务端在 `ServerHello` 中返回了客户端没有请求过的扩展，接收端必须中止握手。

### 2.3 告警定义补充

`document/TLS1.3.txt:4995-4999`

> unsupported_extension: Sent by endpoints receiving any handshake  
> message containing an extension known to be prohibited for  
> inclusion in the given handshake message, or including any  
> extensions in a ServerHello or Certificate not first offered in  
> the corresponding ClientHello or CertificateRequest.

这进一步说明：`ServerHello` 中出现未先由 `ClientHello` 提供的扩展，标准预期是拒绝。

## 3. wolfSSL 源码分析

相关文件：

- `wolfssl-master/src/tls.c`
- `wolfssl-master/src/tls13.c`
- `wolfssl-master/src/internal.c`

### 3.1 解析入口

`wolfssl-master/src/tls13.c:5428-5430`

```c
if ((ret = TLSX_ParseVersion(ssl, input + args->idx,
    args->totalExtSz, *extMsgType, &foundVersion))) {
    return ret;
}
```

先解析 `supported_versions`，随后：

`wolfssl-master/src/tls13.c:5505-5507`

```c
if (args->totalExtSz > 0 && IsAtLeastTLSv1_3(ssl->version)) {
    ret = TLSX_Parse(ssl, input + args->idx, args->totalExtSz,
        *extMsgType, NULL);
```

因此 `ServerHello` 的扩展最终统一进入 `TLSX_Parse(...)`。

### 3.2 已识别扩展的限制

例如 `pre_shared_key`：

`wolfssl-master/src/tls.c:17442-17445`

```c
if (msgType != client_hello &&
    msgType != server_hello) {
    WOLFSSL_ERROR_VERBOSE(EXT_NOT_ALLOWED);
    return EXT_NOT_ALLOWED;
}
```

这说明 wolfSSL 对很多**已识别扩展**确实做了消息类型限制。

### 3.3 未知扩展的默认处理

关键点在这里：

`wolfssl-master/src/tls.c:17668-17670`

```c
default:
    WOLFSSL_MSG("Unknown TLS extension type");
```

这个分支没有：

- `return EXT_NOT_ALLOWED`
- `SendAlert(...)`
- 其他中止握手的动作

它只是记日志，然后继续解析后续扩展。  
这意味着 wolfSSL 对 `ServerHello` 中的**未知扩展**默认是“忽略并继续”，而不是“白名单拒绝”。

### 3.4 告警映射

`wolfssl-master/src/internal.c:35347-35361`

```c
int TranslateErrorToAlert(int err)
{
    switch (err) {
        case WC_NO_ERR_TRACE(BUFFER_ERROR):
            return decode_error;
        case WC_NO_ERR_TRACE(EXT_NOT_ALLOWED):
        case WC_NO_ERR_TRACE(PEER_KEY_ERROR):
        case WC_NO_ERR_TRACE(ECC_PEERKEY_ERROR):
        case WC_NO_ERR_TRACE(BAD_KEY_SHARE_DATA):
        case WC_NO_ERR_TRACE(PSK_KEY_ERROR):
        case WC_NO_ERR_TRACE(INVALID_PARAMETER):
        case WC_NO_ERR_TRACE(HRR_COOKIE_ERROR):
        case WC_NO_ERR_TRACE(BAD_BINDER):
        case WC_NO_ERR_TRACE(DUPLICATE_TLS_EXT_E):
            return illegal_parameter;
```

这表明即使 wolfSSL 走到 `EXT_NOT_ALLOWED`，它通常也会映射为 `illegal_parameter`，而不是 `unsupported_extension`。  
但本次复核更关键的问题其实更前一步：对未知扩展，它根本没有进入拒绝路径。

## 4. 运行时复现实验

复现程序：`201-300/test_tls13_ext_whitelist_269_271.c`

运行日志：`201-300/runtime_269_271_whitelist_check.log`

### 4.1 构造的输入

`201-300/test_tls13_ext_whitelist_269_271.c:150-170`

```c
static const unsigned char shUnknownExt[] = {
    ...
    0xfa, 0xfa, 0x00, 0x02, 0x03, 0x04
};
```

这里构造了一个 TLS 1.3 `ServerHello`：

- 在扩展区插入未知扩展类型 `0xFAFA`
- 同时固定客户端 key share 为 `secp256r1`

这样做是为了避免把密钥组不匹配误判成扩展错误。

### 4.2 运行结果

已执行：

```bash
gcc 201-300/test_tls13_ext_whitelist_269_271.c -Ibuild/wolfssl-weakciphers -Iwolfssl-master -Lbuild/wolfssl-weakciphers -lwolfssl -o 201-300/test_tls13_ext_whitelist_269_271.exe
201-300/test_tls13_ext_whitelist_269_271.exe
```

对应日志片段：

```text
=== ID271-like: ServerHello + unknown extension ===
  wolfSSL_UseKeyShare(secp256r1)=1
  result: pending (want io), lastErr=2
  alert.last_tx: level=-1 code=-1
  alert.last_rx: level=-1 code=-1
```

结果含义：

- 没有进入 fatal error
- 没有发送 fatal alert
- 客户端继续停在 `WOLFSSL_ERROR_WANT_READ`

这说明当前构建下，wolfSSL 客户端对带额外未知扩展的 `ServerHello` 的行为是**继续等待后续握手数据**，而不是立即中止。

## 5. 结论

在 `ServerHello` 中加入额外未知扩展后，wolfSSL 客户端没有立即拒绝。  
这与 RFC 8446 对 `ServerHello MUST only include ...` 的封闭白名单语义不一致。

更准确地说：

- wolfSSL 对很多**已识别扩展**有消息类型约束
- 但对 `ServerHello` 中的**未知扩展**，默认处理是“忽略并继续”
- 因而没有实现 RFC 8446 所要求的严格扩展白名单拒绝

因此 `ID271` 维持“部分满足”是合适的。

