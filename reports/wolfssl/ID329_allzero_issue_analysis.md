# ID329 问题分析：X25519/X448 全零共享秘密检查

## 问题概述

ID329 对应的规范语义是：

- 变量：`key_exchange`
- 动作：`invalid if value check fails`
- 含义：对于 X25519/X448，若计算得到的 Diffie-Hellman 共享秘密为全零值，实现必须将其视为非法并中止处理。

本次分析关注 wolfSSL 是否在默认构建下无条件执行该检查。

## 标准原文

标准文件：`document/TLS1.3.txt`

对应位置：`7.4.2 Elliptic Curve Diffie-Hellman`

原文英文如下：

> For these curves, implementations SHOULD use the approach specified
> in [RFC7748] to calculate the Diffie-Hellman shared secret.
> Implementations MUST check whether the computed Diffie-Hellman shared
> secret is the all-zero value and abort if so, as described in
> Section 6 of [RFC7748].

从该段可以直接得到两点：

1. `SHOULD use the approach specified in [RFC7748]` 是建议级。
2. `MUST check whether ... shared secret is the all-zero value and abort if so` 是强制级。

因此，“是否检查全零共享秘密”不是可选优化项，而是规范明确要求的必做检查。

## wolfSSL 代码描述

### 1. X25519 路径

文件：`wolfssl-master/wolfcrypt/src/curve25519.c`

关键实现位于以下条件编译块：

- `curve25519.c:754`
- `curve25519.c:762`

核心逻辑是：

- 先完成 `curve25519(...)` 共享秘密计算。
- 只有在定义了 `WOLFSSL_ECDHX_SHARED_NOT_ZERO` 时，才遍历输出字节并检查是否全零。
- 若全零，则返回 `ECC_OUT_OF_RANGE_E`。
- 若未定义该宏，则结果直接复制到输出缓冲区并返回成功。

### 2. X448 路径

文件：`wolfssl-master/wolfcrypt/src/curve448.c`

关键实现位于：

- `curve448.c:36`
- `curve448.c:179`
- `curve448.c:186`

其中 `curve448.c:36` 文件头直接注明：

> `WOLFSSL_ECDHX_SHARED_NOT_ZERO: Check ECDH shared secret != 0   default: off`

这说明 wolfSSL 对 X448 的全零共享秘密检查也是通过 `WOLFSSL_ECDHX_SHARED_NOT_ZERO` 控制，且默认关闭。

### 3. 错误码

文件：`wolfssl-master/wolfssl/wolfcrypt/error-crypt.h:199`

对应错误码定义为：

- `ECC_OUT_OF_RANGE_E = -217`

这与启用检查后的运行时结果一致。

## 运行时验证结果

运行时复现记录见：

- `301-400/ID329_allzero_runtime_recheck.md`
- `301-400/id329_allzero_poc.c`

复现实验结论如下。

### 默认构建：未启用 `WOLFSSL_ECDHX_SHARED_NOT_ZERO`

运行结果：

```text
X25519 ret=0, out_len=32, all_zero=1
X448 ret=0, out_len=56, all_zero=1
```

说明：

- wolfSSL 成功返回。
- 输出共享秘密确实为全零。
- 默认构建没有拒绝这一情况。

### 开启 `WOLFSSL_ECDHX_SHARED_NOT_ZERO`

运行结果：

```text
X25519 ret=-217, out_len=32, all_zero=1
X448 ret=-217, out_len=56, all_zero=1
```

说明：

- 同样输入下，wolfSSL 返回 `-217`。
- 即 `ECC_OUT_OF_RANGE_E`。
- 表明该检查逻辑本身存在，但仅在显式开启宏时才生效。

## 不一致原因分析

wolfSSL 与 TLS 1.3 规范不一致的根本原因在于：

1. 规范要求是无条件的 `MUST` 检查。
2. wolfSSL 将该检查放入 `WOLFSSL_ECDHX_SHARED_NOT_ZERO` 条件编译路径。
3. 该宏默认关闭，因此默认构建不会执行这项强制检查。

换句话说，wolfSSL 不是“没有实现该检查”，而是“把规范要求的强制检查降级成了可选构建项”。

这会带来两个直接后果：

1. 默认行为与 TLS 1.3 规范不一致。
2. 只有了解该宏并主动开启的使用者，才会获得符合规范的行为。

## 风险判断

该问题的风险主要体现在协议一致性与密码学健壮性两个方面：

1. 从规范一致性看，默认实现违反了 TLS 1.3 对 X25519/X448 的强制要求。
2. 从实现安全性看，全零共享秘密本应被视为异常输入；若被接受，后续密钥派生会基于异常共享秘密继续执行。
3. 从部署角度看，用户很难仅凭默认构建意识到这一检查未启用，因此容易形成“看似支持 TLS 1.3，实则未完整满足该条规范”的情况。

## 建议

建议分为实现侧和文档侧两部分。

### 实现建议

1. 将 X25519/X448 的全零共享秘密检查改为默认启用。
2. 更稳妥的做法是取消该检查的可选性，使其始终执行，以匹配 TLS 1.3 的 `MUST` 语义。
3. 若出于兼容性原因暂时不能默认启用，也应在 TLS 1.3 相关构建中强制开启该宏，而不是交由普通用户自行决定。

### 文档与测试建议

1. 在构建文档中明确说明：若未开启 `WOLFSSL_ECDHX_SHARED_NOT_ZERO`，则 X25519/X448 的全零共享秘密检查不会执行。
2. 增加回归测试，覆盖：
   - X25519 全零共享秘密输入应失败
   - X448 全零共享秘密输入应失败
3. 在 TLS 1.3 合规性说明中，将该项标记为必须启用的校验，而不是一般增强项。

## 结论

根据标准原文、源码分析和运行时复现结果，可以确认：

- TLS 1.3 明确要求对 X25519/X448 的全零共享秘密执行 `MUST` 级检查。
- wolfSSL 当前默认构建不会执行该检查。
- 只有启用 `WOLFSSL_ECDHX_SHARED_NOT_ZERO` 后，wolfSSL 才会拒绝该非法情况。

因此，ID329 标记为“部分满足”是有依据的；若严格按 TLS 1.3 默认实现合规性来判断，这一行为至少应被视为“默认配置下不满足强制要求”。
