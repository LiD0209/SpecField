# Phase 2 Test Commands

Runtime tests were run against `build\wolfssl-dtls13-audit-tests`, configured with DTLS 1.3 and DTLS CID enabled.

```powershell
& 'D:\project\conditionFuzzing\build\wolfssl-dtls13-audit-tests\tests\unit.test.exe' -test_dtls13_ack_order -test_dtls13_ack_overflow -test_dtls13_ack_dup_write_counter -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Static dynamic-CID symbol check:

```powershell
rg -n "request_connection_id|new_connection_id|cid_immediate|cid_spare|RequestConnectionId|NewConnectionId|ConnectionIdUsage|too_many_cids_requested" wolfssl-master\src wolfssl-master\wolfssl wolfssl-master\tests
```
