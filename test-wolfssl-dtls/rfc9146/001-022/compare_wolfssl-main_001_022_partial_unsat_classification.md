# 部分满足/不满足分类 001-022

- 总数：3
- 状态统计：{'部分满足': 3}
- 风险统计：{'medium': 3}

## CID 地址更新缺少严格 newer(epoch, sequence) 门控
- ID 011：部分满足，风险 medium
  - reason: wolfSSL 只在记录成功解密后更新 pending peer，并通过 DTLS replay window 过滤明显旧包；但普通 DTLS 1.2 路径允许上一 epoch 的窗口记录进入后仍触发 pending peer 更新，未显式要求触发地址变更的记录同时在 epoch 和 sequence number 上都比已接收最新记录更新。
  - standard_check: RFC 9146 的 Peer Address Update 条件同时要求记录成功去保护、CID 有效、并且 datagram 在 epoch 和 sequence number 上比已接收最新 datagram 更新。
  - code_check: wolfSSL 保存 pendingPeer，并且只有解密后调用 dtlsProcessPendingPeer(ssl, 1) 更新 peer；但 _DtlsCheckWindow 接受 nextEpoch-1 的 previous window，dtlsProcessPendingPeer 不检查该记录是否比最新记录更新。
  - test_check: verify_wolfssl_dtls_cid_001_022.py::test_peer_update_lacks_strict_newer_gate 通过，确认 previous-epoch 分支和无 newer gate 的 peer 更新路径同时存在。
  - decision_reason: 已实现 CID 匹配和解密成功门控；缺失对地址更新专用的 strict newer(epoch, sequence) 判断，因此为 confirmed_partial。
- ID 017：部分满足，风险 medium
  - reason: wolfSSL 只在记录成功解密后更新 pending peer，并通过 DTLS replay window 过滤明显旧包；但普通 DTLS 1.2 路径允许上一 epoch 的窗口记录进入后仍触发 pending peer 更新，未显式要求触发地址变更的记录同时在 epoch 和 sequence number 上都比已接收最新记录更新。
  - standard_check: RFC 9146 的 Peer Address Update 条件同时要求记录成功去保护、CID 有效、并且 datagram 在 epoch 和 sequence number 上比已接收最新 datagram 更新。
  - code_check: wolfSSL 保存 pendingPeer，并且只有解密后调用 dtlsProcessPendingPeer(ssl, 1) 更新 peer；但 _DtlsCheckWindow 接受 nextEpoch-1 的 previous window，dtlsProcessPendingPeer 不检查该记录是否比最新记录更新。
  - test_check: verify_wolfssl_dtls_cid_001_022.py::test_peer_update_lacks_strict_newer_gate 通过，确认 previous-epoch 分支和无 newer gate 的 peer 更新路径同时存在。
  - decision_reason: 已实现 CID 匹配和解密成功门控；缺失对地址更新专用的 strict newer(epoch, sequence) 判断，因此为 confirmed_partial。
## CMake 启用路径把 DTLS CID 绑定到 DTLS 1.3
- ID 018：部分满足，风险 medium
  - reason: 源码记录层实现包含 DTLS 1.2 tls12_cid(25) 路径，也没有在 DTLS 1.3 记录中使用 tls12_cid 内容类型；但 CMake 选项在启用 WOLFSSL_DTLS_CID 且未启用 WOLFSSL_DTLS13 时直接报错，导致 CMake 构建路径不能单独启用 DTLS 1.2 CID。
  - standard_check: RFC 9146 将 tls12_cid(25) 定义为 DTLS 1.2 content type；DTLS 1.3 CID 使用不同记录头机制。
  - code_check: 记录层代码正确把 DTLS 1.2 CID type 定义为 25，并在 DTLS 1.2 CID 记录中使用；但 CMakeLists.txt 在 WOLFSSL_DTLS_CID 且未启用 WOLFSSL_DTLS13 时 FATAL_ERROR。
  - test_check: verify_wolfssl_dtls_cid_001_022.py::test_cmake_cid_requires_dtls13 通过，确认 CMake 约束存在；test_constants_and_record_paths 通过，确认数据面常量和路径存在。
  - decision_reason: 数据面基本满足，但 CMake 启用路径与 DTLS 1.2 CID 的适用范围不一致，confirmed_partial。
