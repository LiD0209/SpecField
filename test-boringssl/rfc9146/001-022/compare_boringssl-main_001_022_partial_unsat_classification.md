# Partial/Unsatisfied Classification

- Total reviewed: 13
- Unsatisfied: 10
- Partial: 3

| category | count | unsatisfied | partial | risk | items |
|---|---:|---:|---:|---|---|
| missing DTLS 1.2 CID record format | 2 | 2 | 0 | {'medium': 2} | 005, 006 |
| missing DTLSInnerPlaintext for RFC 9146 | 2 | 2 | 0 | {'medium': 2} | 010, 013 |
| missing CID peer address update | 2 | 2 | 0 | {'medium': 2} | 011, 017 |
| generic limit only, no CID-specific field | 1 | 0 | 1 | {'low': 1} | 012 |
| missing CID MAC/AAD construction | 2 | 2 | 0 | {'high': 2} | 014, 016 |
| missing tls12_cid content type | 2 | 2 | 0 | {'medium': 2} | 015, 018 |
| DTLS 1.3 padding only, no RFC 9146 DTLS 1.2 CID padding | 2 | 0 | 2 | {'low': 2} | 021, 022 |

## Phase 2 Verification

### 005 `cid` - confirmed_unsatisfied
- standard_check: 已复核 Section 3 and Section 7。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/extensions.cc:3951; boringssl-main/ssl/extensions.cc:4074; boringssl-main/ssl/extensions.cc:4172; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 要求非零 CID 协商后、加密启用后用 CID-enhanced record format 和 tls12_cid 发送。BoringSSL DTLS 1.2 写路径仍写普通 DTLSPlaintext header，没有 CID 字段或 tls12_cid。

### 006 `cid` - confirmed_unsatisfied
- standard_check: 已复核 Section 4 Record Layer Extensions。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/extensions.cc:3951; boringssl-main/ssl/extensions.cc:4074; boringssl-main/ssl/extensions.cc:4172; boringssl-main/ssl/dtls_record.cc:235; boringssl-main/ssl/dtls_record.cc:237; boringssl-main/ssl/dtls_record.cc:238; boringssl-main/ssl/dtls_record.cc:239; boringssl-main/ssl/dtls_record.cc:257; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 的 DTLSCiphertext.cid 字段应等于协商 CID，长度为 cid_length。BoringSSL 没有 negotiation state，也没有在 DTLS 1.2 record header 中解析或写入 CID 字段。

### 010 `enc_content` - confirmed_unsatisfied
- standard_check: 已复核 Section 4 Record Layer Extensions。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 要求 enc_content 是序列化 DTLSInnerPlaintext 的加密结果。BoringSSL 仅在 DTLS 1.3 路径附加内部 content type；DTLS 1.2 CID 路径不存在。

### 011 `epoch` - confirmed_unsatisfied
- standard_check: 已复核 Section 6 Peer Address Update。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:25; boringssl-main/ssl/dtls_record.cc:31; boringssl-main/ssl/dtls_record.cc:42; boringssl-main/ssl/dtls_record.cc:366; boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 对 CID 记录源地址变化要求验证后且 epoch/sequence 更新。BoringSSL 有 replay bitmap，但没有 CID 到连接查找和 peer address update 状态机，因此没有该地址更新门控。

### 012 `length_of_DTLSInnerPlaintext` - confirmed_partial
- standard_check: 已复核 Section 5 Record Payload Protection。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347; boringssl-main/ssl/internal.h:3013。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: BoringSSL 对普通/DTLS 1.3 plaintext 有 SSL3_RT_MAX_PLAIN_LENGTH 限制，但没有 RFC 9146 length_of_DTLSInnerPlaintext 字段和 CID-specific 检查。

### 013 `length_of_DTLSInnerPlaintext` - confirmed_unsatisfied
- standard_check: 已复核 Section 5 Record Payload Protection。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:235; boringssl-main/ssl/dtls_record.cc:237; boringssl-main/ssl/dtls_record.cc:238; boringssl-main/ssl/dtls_record.cc:239; boringssl-main/ssl/dtls_record.cc:257; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 要求 length_of_DTLSInnerPlaintext 是序列化 DTLSInnerPlaintext 的两字节长度。BoringSSL DTLS 1.2 记录长度表示 ciphertext/body 长度，没有 CID 内部明文长度字段。

### 014 `outer_type` - confirmed_unsatisfied
- standard_check: 已复核 Section 5.1 and 5.3。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 MAC/AAD 构造以 tls12_cid、cid_length、CID 和内部长度作为输入。BoringSSL AEAD Open/SealScatter 只使用 record.header 作为 AAD，没有 CID AAD 构造。

### 015 `outer_type` - confirmed_unsatisfied
- standard_check: 已复核 Section 4 Record Layer Extensions。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558; boringssl-main/ssl/extensions.cc:3951; boringssl-main/ssl/extensions.cc:4074; boringssl-main/ssl/extensions.cc:4172。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 要求携带 CID 的 DTLSCiphertext.outer_type 固定为 tls12_cid(25)。BoringSSL 无 tls12_cid 常量，DTLS 1.2 写路径直接使用调用方 type。

### 016 `seq_num_placeholder` - confirmed_unsatisfied
- standard_check: 已复核 Section 5 Record Payload Protection。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 modified MAC/AAD 使用 8 字节 0xff seq_num_placeholder。BoringSSL 没有该字段或等价构造。

### 017 `sequence_number` - confirmed_unsatisfied
- standard_check: 已复核 Section 6 Peer Address Update。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:25; boringssl-main/ssl/dtls_record.cc:31; boringssl-main/ssl/dtls_record.cc:42; boringssl-main/ssl/dtls_record.cc:366; boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: 与 epoch 条件相同，BoringSSL 记录层跟踪 sequence replay，但没有 CID peer address update 逻辑，因此不存在用于地址更新的 newest datagram sequence 检查。

### 018 `tls12_cid` - confirmed_unsatisfied
- standard_check: 已复核 Section 10.3 New Entry in TLS ContentType Registry。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:170; boringssl-main/ssl/dtls_record.cc:171; boringssl-main/ssl/dtls_record.cc:172; boringssl-main/ssl/dtls_record.cc:173; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: RFC 9146 分配 tls12_cid(25)，且仅适用于 DTLS 1.2。BoringSSL 没有 tls12_cid content type；DTLS 1.3 的 CID bit 反而被显式拒绝。

### 021 `zeros` - confirmed_partial
- standard_check: 已复核 Section 4 Record Layer Extensions。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: BoringSSL DTLS 1.3 路径支持 encrypted inner type 后的零填充剥离，但 RFC 9146 要求的是 DTLS 1.2 CID 的 DTLSInnerPlaintext padding；该路径不存在。

### 022 `zeros` - confirmed_partial
- standard_check: 已复核 Section 4 Record Layer Extensions。该条要求适用于 RFC 9146 DTLS 1.2 CID 记录或 CID peer address update，而不是普通 DTLS 1.2 记录。
- code_check: 已复核证据路径：boringssl-main/ssl/dtls_record.cc:327; boringssl-main/ssl/dtls_record.cc:328; boringssl-main/ssl/dtls_record.cc:329; boringssl-main/ssl/dtls_record.cc:330; boringssl-main/ssl/dtls_record.cc:343; boringssl-main/ssl/dtls_record.cc:347; boringssl-main/ssl/dtls_record.cc:427; boringssl-main/ssl/dtls_record.cc:431; boringssl-main/ssl/dtls_record.cc:533; boringssl-main/ssl/dtls_record.cc:540; boringssl-main/ssl/dtls_record.cc:548; boringssl-main/ssl/dtls_record.cc:556; boringssl-main/ssl/dtls_record.cc:558。BoringSSL 主库没有 connection_id(54) 扩展状态、tls12_cid(25) 内容类型、CID 字段解析/发送或 RFC 9146 CID AAD 构造。
- test_check: 运行 tests/verify_rfc9146_cid_support.py，8 个结构化断言全部 PASS。由于 cmake/ninja/cl 不可用，未编译 upstream C++ 测试；该限制已记录在元数据和日志中。
- decision_reason: 零填充值要求在 BoringSSL 的 DTLS 1.3 trailing zero 逻辑中体现，但没有 RFC 9146 DTLS 1.2 CID DTLSInnerPlaintext 构造，因此只部分满足。
