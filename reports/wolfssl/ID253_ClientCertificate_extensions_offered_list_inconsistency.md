# ID253：客户端 Certificate 扩展与 offered list 对应关系不一致

## 结论

`ID253` 讨论的是：客户端发送的 `Certificate` 消息中的扩展，是否必须对应服务器之前在 `CertificateRequest` 中给出的扩展列表。

标准要求是“必须对应”。wolfSSL 当前代码虽然会解析 `CertificateEntry` 中的扩展，但在当前构建下，没有看到一条稳定生效的“如果这个扩展没有先出现在 `CertificateRequest` 中，就拒绝”的硬校验路径。因此，这一条不能算严格满足标准。

## 标准原文

标准文本在 [TLS1.3.txt](/d:/project/conditionFuzzing/document/TLS1.3.txt:3599) 这一段：

- [TLS1.3.txt:3599](/d:/project/conditionFuzzing/document/TLS1.3.txt:3599)
- [TLS1.3.txt:3600](/d:/project/conditionFuzzing/document/TLS1.3.txt:3600)
- [TLS1.3.txt:3601](/d:/project/conditionFuzzing/document/TLS1.3.txt:3601)
- [TLS1.3.txt:3602](/d:/project/conditionFuzzing/document/TLS1.3.txt:3602)
- [TLS1.3.txt:3603](/d:/project/conditionFuzzing/document/TLS1.3.txt:3603)
- [TLS1.3.txt:3604](/d:/project/conditionFuzzing/document/TLS1.3.txt:3604)
- [TLS1.3.txt:3605](/d:/project/conditionFuzzing/document/TLS1.3.txt:3605)
- [TLS1.3.txt:3606](/d:/project/conditionFuzzing/document/TLS1.3.txt:3606)
- [TLS1.3.txt:3607](/d:/project/conditionFuzzing/document/TLS1.3.txt:3607)
- [TLS1.3.txt:3608](/d:/project/conditionFuzzing/document/TLS1.3.txt:3608)

原文上下文如下：

```text
extensions:  A set of extension values for the CertificateEntry.  The
"Extension" format is defined in Section 4.2.  Valid extensions
for server certificates at present include the OCSP Status
extension [RFC6066] and the SignedCertificateTimestamp extension
[RFC6962]; future extensions may be defined for this message as
well.  Extensions in the Certificate message from the server MUST
correspond to ones from the ClientHello message.  Extensions in
the Certificate message from the client MUST correspond to
extensions in the CertificateRequest message from the server.  If
an extension applies to the entire chain, it SHOULD be included in
the first CertificateEntry.
```

其中和 `ID253` 直接对应的完整原文是：

`Extensions in the Certificate message from the client MUST correspond to extensions in the CertificateRequest message from the server.`

这句话的关键词是 `MUST correspond`。  
标准要求的不是“扩展格式合法即可”，而是“客户端证书里的扩展，必须属于服务器之前在 `CertificateRequest` 中已经给出的那组扩展”。

## wolfSSL 源代码

### 1. CertificateEntry 扩展确实会被解析

在 [internal.c:15920](/d:/project/conditionFuzzing/wolfssl-master/src/internal.c:15920) 到 [internal.c:15936](/d:/project/conditionFuzzing/wolfssl-master/src/internal.c:15936)：

```c
args->exts[args->totalCerts].length = extSz;
args->exts[args->totalCerts].buffer = input + args->idx;
args->idx += extSz;
listSz -= extSz + OPAQUE16_LEN;
WOLFSSL_MSG_EX("\tParsing %d bytes of cert extensions",
    args->exts[args->totalCerts].length);
#if !defined(NO_TLS)
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST)
ssl->response_idx = args->totalCerts;
#endif
ret = TLSX_Parse(ssl, args->exts[args->totalCerts].buffer,
    (word16)args->exts[args->totalCerts].length,
    certificate, NULL);
#endif /* !NO_TLS */
if (ret < 0) {
    WOLFSSL_ERROR_VERBOSE(ret);
    ERROR_OUT(ret, exit_ppc);
}
```

这段代码说明：

- `CertificateEntry` 里的扩展不是被忽略了；
- wolfSSL 会先取出每个证书条目里的扩展块；
- 然后统一送入 `TLSX_Parse(..., msgType=certificate, ...)`。

所以问题不在“有没有解析”，而在“解析时有没有落实标准要求的 offered list 对应关系检查”。

### 2. TLSX_Parse 是通用扩展解析入口

在 [tls.c:16999](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:16999) 到 [tls.c:17020](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17020)：

```c
int TLSX_Parse(WOLFSSL* ssl, const byte* input, word16 length, byte msgType,
                                                                 Suites *suites)
{
    int ret = 0;
    word16 offset = 0;
    byte isRequest = (msgType == client_hello ||
                      msgType == certificate_request);
...
    byte seenType[SEMAPHORE_SIZE];  /* Seen known extensions. */

    if (!ssl || !input || (isRequest && !suites))
        return BAD_FUNC_ARG;

    /* No known extensions seen yet. */
    XMEMSET(seenType, 0, sizeof(seenType));
```

这里有一个重要点：

- `isRequest` 只把 `client_hello` 和 `certificate_request` 当作“请求类消息”；
- `certificate` 不属于这里的 `isRequest`。

这意味着解析 `Certificate` 扩展时，wolfSSL 走的是“响应/接收端路径”，不是“请求路径”。

### 3. status_request 在 certificate 消息里是允许进入解析分支的

在 [tls.c:17230](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17230) 到 [tls.c:17250](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17250)：

```c
case TLSX_STATUS_REQUEST:
    WOLFSSL_MSG("Certificate Status Request extension received");
...
#ifdef WOLFSSL_TLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        if (msgType != client_hello &&
            msgType != certificate_request &&
            msgType != certificate)
            return EXT_NOT_ALLOWED;
    }
    else
#endif
    {
        if (msgType != client_hello &&
            msgType != server_hello)
            return EXT_NOT_ALLOWED;
    }
    ret = CSR_PARSE(ssl, input + offset, size, isRequest);
```

这段代码说明两件事：

- `status_request` 这个扩展在 TLS 1.3 中，允许出现在 `certificate` 消息里；
- 但“允许这种扩展类型出现在这个消息里”，不等于“它已经验证过必须来自服务器之前的 `CertificateRequest` 列表”。

也就是说，这里只是做了“消息位置是否合法”的检查，还不是“来源是否来自 offered list”的检查。

### 4. 如果相关功能启用，wolfSSL 本来是有“没先请求就拒绝”的逻辑的

在 [tls.c:3657](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3657) 到 [tls.c:3705](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3705)：

```c
static int TLSX_CSR_Parse(WOLFSSL* ssl, const byte* input, word16 length,
                          byte isRequest)
{
...
    if (!isRequest) {
#ifndef NO_WOLFSSL_CLIENT
        extension = TLSX_Find(ssl->extensions, TLSX_STATUS_REQUEST);
        csr = extension ? (CertificateStatusRequest*)extension->data : NULL;

        if (!csr) {
            /* look at context level */
            extension = TLSX_Find(ssl->ctx->extensions, TLSX_STATUS_REQUEST);
            csr = extension ? (CertificateStatusRequest*)extension->data : NULL;

            if (!csr) /* unexpected extension */
                return TLSX_HandleUnsupportedExtension(ssl);

            /* enable extension at ssl level */
            ret = TLSX_UseCertificateStatusRequest(&ssl->extensions,
                                     csr->status_type, csr->options, ssl,
                                     ssl->heap, ssl->devId);
```

这段逻辑非常关键：

- 当解析到 `Certificate` 中的 `status_request` 时，wolfSSL 会先看看本端是否已经有这个扩展记录；
- 这个“已有记录”在语义上，就是“之前通过协商/配置出现过”；
- 如果找不到，它就把这个扩展视为 `unexpected extension`。

而 [tls.c:1712](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:1712) 到 [tls.c:1718](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:1718) 给出了真正的拒绝动作：

```c
int TLSX_HandleUnsupportedExtension(WOLFSSL* ssl)
{
    SendAlert(ssl, alert_fatal, unsupported_extension);
    WOLFSSL_ERROR_VERBOSE(UNSUPPORTED_EXTENSION);
    return UNSUPPORTED_EXTENSION;
}
```

这条路径本身其实很符合标准要求：

- 如果客户端证书里出现了一个本端没有先收到请求的扩展，
- 就应当拒绝。

### 5. 但当前构建里，这条校验路径并没有真正生效

在 [tls.c:3992](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3992) 到 [tls.c:3995](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:3995)：

```c
#define CSR_FREE_ALL(data, heap) WC_DO_NOTHING
#define CSR_GET_SIZE(a, b)    0
#define CSR_WRITE(a, b, c)    0
#define CSR_PARSE(a, b, c, d) 0
```

这说明在当前默认构建里：

- `CSR_PARSE` 不是实际函数；
- 它被宏替换成了直接返回 `0`；
- 也就是“直接成功，不做检查”。

当前构建配置在 [options.h:81](/d:/project/conditionFuzzing/build/wolfssl-default/wolfssl/options.h:81) 到 [options.h:150](/d:/project/conditionFuzzing/build/wolfssl-default/wolfssl/options.h:150) 也能看到：

```c
#undef HAVE_CERTIFICATE_STATUS_REQUEST
/* #undef HAVE_CERTIFICATE_STATUS_REQUEST */
...
#undef HAVE_OCSP
/* #undef HAVE_OCSP */
...
#undef HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS
```

也就是说：

- 扩展框架在；
- 但 `Certificate status request` 相关的专门校验逻辑没编进来。

### 6. 未识别扩展默认只记日志，不拒绝

在 [tls.c:17668](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17668) 到 [tls.c:17670](/d:/project/conditionFuzzing/wolfssl-master/src/tls.c:17670)：

```c
default:
    WOLFSSL_MSG("Unknown TLS extension type");
```

这意味着：

- 对于未知扩展，当前实现默认只是记一条日志；
- 并不会因为“它没有出现在 `CertificateRequest` 列表里”而自动拒绝。

## 为什么与标准不一致

标准要求的是：

- 客户端 `Certificate` 中的扩展，必须对应服务器之前在 `CertificateRequest` 中给出的扩展列表。

当前实现的行为更接近：

- `CertificateEntry` 中的扩展会被统一解析；
- 已知扩展会检查“它能不能出现在 `certificate` 消息里”；
- 只有在相关功能启用时，才可能继续检查“它是不是先前请求过的扩展”；
- 当前构建中，这条深一层的校验路径被宏裁掉了；
- 未知扩展也不会因为“不在前序列表里”而被统一拒绝。

所以，不一致的根因是：

- 标准要求检查“它是否来自服务器之前给出的扩展列表”；
- 当前构建下的 wolfSSL 更像是在检查“扩展类型和消息位置是否基本允许”，没有把 offered list 对应关系当成硬门槛。

## 证据范围说明

当前最小探针是 [test_id253_254_tlsx_parse_runtime.c](/d:/project/conditionFuzzing/201-300/test_id253_254_tlsx_parse_runtime.c:1)。

这个探针在当前默认静态构建下：

- 客户端对象可以初始化；
- 服务端对象初始化失败；

因此：

- `ID254` 有直接运行时证据；
- `ID253` 这里主要依据源码路径和解析流程来判断。

这也是为什么 `ID253` 这份文档以源码分析为主，而不是像 `ID254` 那样直接用运行结果下结论。
