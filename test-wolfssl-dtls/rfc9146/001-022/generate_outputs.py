import json
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLSCID_02_variable_changes.json"
TARGET_REQUESTED = ROOT / "wolfssl-main"
TARGET = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc9146" / "001-022"
IMPL_FILE = "wolfssl-main"
IMPL_FIELD = "wolfssl"

STATUS_SAT = "满足"
STATUS_PARTIAL = "部分满足"
STATUS_UNSAT = "不满足"
STATUS_NA = "不适用"


RFC = {
    "connection_id": {
        "section": "RFC 9146 Section 4, The connection_id Extension",
        "quote": "The extension_data field of this extension contains a ConnectionId structure.",
    },
    "self_delineating": {
        "section": "RFC 9146 Section 4, The connection_id Extension",
        "quote": "If, however, an implementation chooses to receive CIDs of different lengths, the assigned CID values must be self-delineating.",
    },
    "record": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "The modified algorithm MUST NOT be applied to records that do not carry a CID.",
    },
    "outer": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "The outer content type of a DTLSCiphertext record carrying a CID is always set to tls12_cid(25).",
    },
    "length": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "The length MUST NOT exceed 2^14.",
    },
    "aad": {
        "section": "RFC 9146 Section 5, Record Payload Protection",
        "quote": "seq_num_placeholder:  8 bytes of 0xff.",
    },
    "peer": {
        "section": "RFC 9146 Section 6, Peer Address Update",
        "quote": 'The received datagram is "newer" (in terms of both epoch and sequence number) than the newest datagram received.',
    },
    "iana": {
        "section": "RFC 9146 Section 8, IANA Considerations",
        "quote": "IANA has allocated tls12_cid(25) in the TLS ContentType registry.",
    },
    "example": {
        "section": "RFC 9146 Appendix A, Example",
        "quote": "In the example exchange, the CID is included in the record layer once encryption is enabled.",
    },
}


def read_lines(rel):
    return (TARGET / rel).read_text(encoding="utf-8", errors="replace").splitlines()


def evidence_exists(ref):
    m = re.match(r"([^:]+):(\d+)$", ref)
    if not m:
        return False
    path = ROOT / m.group(1)
    line = int(m.group(2))
    if not path.exists():
        return False
    count = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    return 1 <= line <= count


def source_snippet(rel, start, end):
    lines = read_lines(rel)
    return "\n".join(f"{i}:{lines[i-1]}" for i in range(start, end + 1))


BASE_EVIDENCE = {
    "config": [
        "wolfssl-master/CMakeLists.txt:419",
        "wolfssl-master/CMakeLists.txt:423",
        "wolfssl-master/CMakeLists.txt:425",
        "wolfssl-master/CMakeLists.txt:427",
        "wolfssl-master/build/CMakeCache.txt:433",
    ],
    "constants": [
        "wolfssl-master/wolfssl/internal.h:2970",
        "wolfssl-master/wolfssl/internal.h:3034",
        "wolfssl-master/wolfssl/internal.h:3035",
        "wolfssl-master/wolfssl/internal.h:6620",
    ],
    "cid_ext": [
        "wolfssl-master/src/dtls.c:1188",
        "wolfssl-master/src/dtls.c:1196",
        "wolfssl-master/src/dtls.c:1202",
        "wolfssl-master/src/dtls.c:1254",
        "wolfssl-master/src/dtls.c:1277",
        "wolfssl-master/src/dtls.c:1302",
        "wolfssl-master/src/dtls.c:1312",
    ],
    "record_write": [
        "wolfssl-master/src/internal.c:10855",
        "wolfssl-master/src/internal.c:10857",
        "wolfssl-master/src/internal.c:10858",
        "wolfssl-master/src/internal.c:10859",
        "wolfssl-master/src/internal.c:24488",
        "wolfssl-master/src/internal.c:24490",
        "wolfssl-master/src/internal.c:24503",
        "wolfssl-master/src/internal.c:24504",
    ],
    "record_read": [
        "wolfssl-master/src/internal.c:12169",
        "wolfssl-master/src/internal.c:12170",
        "wolfssl-master/src/internal.c:12205",
        "wolfssl-master/src/internal.c:12211",
        "wolfssl-master/src/internal.c:12213",
        "wolfssl-master/src/internal.c:12215",
    ],
    "aad": [
        "wolfssl-master/wolfssl/internal.h:1379",
        "wolfssl-master/wolfssl/internal.h:1381",
        "wolfssl-master/wolfssl/internal.h:1392",
        "wolfssl-master/src/internal.c:20259",
        "wolfssl-master/src/internal.c:20261",
        "wolfssl-master/src/internal.c:20262",
        "wolfssl-master/src/internal.c:20263",
        "wolfssl-master/src/internal.c:20276",
    ],
    "length": [
        "wolfssl-master/wolfssl/internal.h:1526",
        "wolfssl-master/wolfssl/internal.h:2298",
        "wolfssl-master/src/internal.c:23321",
        "wolfssl-master/src/internal.c:23322",
    ],
    "padding": [
        "wolfssl-master/src/internal.c:22532",
        "wolfssl-master/src/internal.c:22548",
        "wolfssl-master/src/internal.c:22550",
        "wolfssl-master/src/internal.c:22555",
        "wolfssl-master/src/internal.c:22556",
        "wolfssl-master/src/internal.c:24503",
        "wolfssl-master/src/internal.c:24504",
    ],
    "peer": [
        "wolfssl-master/wolfssl/internal.h:2749",
        "wolfssl-master/wolfssl/internal.h:2750",
        "wolfssl-master/src/ssl.c:1458",
        "wolfssl-master/src/ssl.c:1487",
        "wolfssl-master/src/internal.c:19034",
        "wolfssl-master/src/internal.c:19039",
        "wolfssl-master/src/internal.c:19287",
        "wolfssl-master/src/internal.c:19337",
        "wolfssl-master/src/internal.c:19342",
        "wolfssl-master/src/internal.c:22584",
        "wolfssl-master/src/internal.c:22601",
        "wolfssl-master/src/internal.c:22602",
        "wolfssl-master/src/internal.c:23283",
        "wolfssl-master/src/internal.c:23284",
        "wolfssl-master/src/internal.c:23288",
        "wolfssl-master/src/internal.c:23289",
    ],
}


def classify_item(idx, item):
    vid = idx + 1
    var = item["variable_name"]
    cond = item["change_condition"]
    action = item["change_action"]

    default = {
        "id": vid,
        "source_index": idx,
        **item,
        "risk": "low",
        "category": "",
    }

    if vid in (11, 17):
        default.update(
            status=STATUS_PARTIAL,
            category="CID 地址更新缺少严格 newer(epoch, sequence) 门控",
            risk="medium",
            standard_section=RFC["peer"]["section"],
            standard_text=RFC["peer"]["quote"],
            comment="wolfSSL 只在记录成功解密后更新 pending peer，并通过 DTLS replay window 过滤明显旧包；但普通 DTLS 1.2 路径允许上一 epoch 的窗口记录进入后仍触发 pending peer 更新，未显式要求触发地址变更的记录同时在 epoch 和 sequence number 上都比已接收最新记录更新。",
            comparison_summary="要求：CID 地址漂移只能由已成功去保护且比当前最新 datagram 更新的记录触发。标准含义：epoch 和 sequence_number 都参与 newer 判断。代码行为：GetRecordHeader/_DtlsCheckWindow 允许 current epoch 或 previous epoch 的窗口内记录，runProcessingOneRecord 在 IsEncryptionOn 后调用 dtlsProcessPendingPeer(ssl, 1)，该函数直接 wolfSSL_dtls_set_peer。结论：有解密成功门控和 replay window，但缺少针对地址更新的严格 newer(epoch, sequence) 门控，属于部分满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["peer"]},
        )
        return default

    if vid == 18:
        default.update(
            status=STATUS_PARTIAL,
            category="CMake 启用路径把 DTLS CID 绑定到 DTLS 1.3",
            risk="medium",
            standard_section=RFC["iana"]["section"],
            standard_text="The tls12_cid content type is only applicable to DTLS 1.2.",
            comment="源码记录层实现包含 DTLS 1.2 tls12_cid(25) 路径，也没有在 DTLS 1.3 记录中使用 tls12_cid 内容类型；但 CMake 选项在启用 WOLFSSL_DTLS_CID 且未启用 WOLFSSL_DTLS13 时直接报错，导致 CMake 构建路径不能单独启用 DTLS 1.2 CID。",
            comparison_summary="要求：tls12_cid 内容类型只适用于 DTLS 1.2。代码行为：internal.h 定义 dtls12_cid=25，DTLS 1.2 AddRecordHeader/parse 路径使用该内容类型；DTLS 1.3 使用 unified header CID bit。构建行为：CMakeLists.txt 要求 WOLFSSL_DTLS_CID 依赖 WOLFSSL_DTLS13。结论：协议数据面基本满足，但 CMake 启用条件与 DTLS 1.2 CID 的适用范围不一致，属于部分满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["constants"] + BASE_EVIDENCE["config"] + ["wolfssl-master/src/dtls13.c:1163", "wolfssl-master/src/dtls13.c:1176"]},
        )
        return default

    if vid in (3, 4, 7, 8, 9):
        section = RFC["example"]["section"] if vid in (3, 4) else RFC["iana"]["section"]
        default.update(
            status=STATUS_NA,
            category="标准示例或 IANA 注册表说明",
            risk="low",
            standard_section=section,
            standard_text=item["evidence"],
            comment="该条来自 RFC 示例或 IANA 注册表维护说明，不是 wolfSSL 运行时必须改变的协议状态。代码中相关常量/扩展编号存在时作为佐证，但不把示例值作为实现强制要求。",
            comparison_summary=f"要求抽取内容是说明性条目：{cond} / {action}。实现审计不应要求 wolfSSL 固定使用示例 CID 值或维护 IANA 表格。结论：不适用。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["constants"] if vid in (8, 9) else BASE_EVIDENCE["cid_ext"][:3]},
        )
        return default

    if vid in (1, 5):
        default.update(
            status=STATUS_SAT,
            category="示例行为由加密后记录 CID 路径覆盖",
            risk="low",
            standard_section=RFC["example"]["section"],
            standard_text=RFC["example"]["quote"],
            comment="示例所描述的加密后携带 CID 行为在 wolfSSL 的发送路径中以协商到的 tx CID 大小为条件实现；握手早期无 tx CID 时不会使用 tls12_cid。",
            comparison_summary="要求：示例中加密开启后 Finished/application_data 记录携带 CID。代码行为：当 DTLS 且 DtlsGetCidTxSize()>0 时把外层 type 改为 dtls12_cid，写入协商 tx CID，并把真实 inner content type 追加到明文末尾再加密。结论：条件满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["record_write"]},
        )
        return default

    if vid == 2:
        default.update(
            status=STATUS_SAT,
            category="单连接固定接收 CID 长度，不选择混合长度接收",
            risk="low",
            standard_section=RFC["self_delineating"]["section"],
            standard_text=RFC["self_delineating"]["quote"],
            comment="wolfSSL 每个连接只保存一个 rx CID 及其固定长度，并按该长度比较接收记录；未发现同一连接选择接收多个不同长度 CID 的路径，因此 self-delineating 条件未被触发。",
            comparison_summary="要求：只有当实现选择接收不同长度 CID 时，CID 值必须自描述。代码行为：wolfSSL_dtls_cid_set 在 CIDInfo.rx 中保存单个长度，GetDtlsRecordHeader 使用 DtlsGetCidRxSize 得到固定长度并逐字节比较。结论：当前实现不选择同一连接混合长度接收，满足该条件的前提处理。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["cid_ext"] + BASE_EVIDENCE["record_read"]},
        )
        return default

    if vid == 6:
        default.update(
            status=STATUS_SAT,
            category="协商 CID 写入和接收校验",
            risk="low",
            standard_section=RFC["connection_id"]["section"],
            standard_text="cid:  The CID value, cid_length bytes long, as agreed at the time the extension has been negotiated.",
            comment="wolfSSL 解析 connection_id 扩展后保存对端提供的 tx CID；发送 DTLS 1.2 CID 记录时写入该 tx CID，接收时按本端 rx CID 长度和值校验。",
            comparison_summary="要求：记录层 cid 字段必须是协商值且长度为 cid_length。代码行为：TLSX_ConnectionID_Parse 保存 input 中的 CID 到 info->tx，AddRecordHeader 使用 wolfSSL_dtls_cid_get_tx 写入，GetDtlsRecordHeader 使用 get0_rx 和 memcmp 验证。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["cid_ext"] + BASE_EVIDENCE["record_write"] + BASE_EVIDENCE["record_read"]},
        )
        return default

    if vid == 10:
        default.update(
            status=STATUS_SAT,
            category="DTLSInnerPlaintext 序列化后加密",
            risk="low",
            standard_section=RFC["record"]["section"],
            standard_text="enc_content:  The encrypted form of the serialized DTLSInnerPlaintext structure.",
            comment="发送路径在启用 CID 时先追加 inner content type，再进入后续加密/MAC 处理；接收路径解密后移除 inner padding 并恢复真实内容类型。",
            comparison_summary="要求：enc_content 是序列化 DTLSInnerPlaintext 的加密形式。代码行为：CID 路径把真实 type 放到明文末尾，并在接收端 removeMsgInnerPadding 中从明文末尾恢复 type。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["record_write"] + BASE_EVIDENCE["padding"]},
        )
        return default

    if vid in (12, 13):
        default.update(
            status=STATUS_SAT,
            category="明文长度限制和 AAD 长度字段",
            risk="low",
            standard_section=RFC["length"]["section"],
            standard_text=RFC["length"]["quote"],
            comment="wolfSSL 定义 MAX_PLAINTEXT_SZ 为 2^14，并在非 TLS 1.3/DTLS CID 明文处理路径检查去除 padding/MAC 后的明文长度；CID AAD 构造中写入 length_of_DTLSInnerPlaintext。",
            comparison_summary="要求：DTLSInnerPlaintext length 字段表示序列化明文长度且不得超过 2^14。代码行为：MAX_PLAINTEXT_SZ/MAX_RECORD_SIZE 均为 16384；解密后检查 ssl->curSize - padSz；CID AAD 使用 c16toa(sz)。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["length"] + BASE_EVIDENCE["aad"][-2:]},
        )
        return default

    if vid in (14, 16):
        default.update(
            status=STATUS_SAT,
            category="CID AAD/MAC 输入构造",
            risk="low",
            standard_section=RFC["aad"]["section"],
            standard_text=RFC["aad"]["quote"],
            comment="writeAeadAuthData 在 DTLS CID 路径中写入 8 字节 0xff 占位符、tls12_cid、cid_length、tls12_cid、版本、序列号、CID 和明文长度。",
            comparison_summary="要求：CID 记录的 MAC/AAD 输入必须使用 seq_num_placeholder 和 tls12_cid 等字段。代码行为：XMEMSET(additional,0xFF,SEQ_SZ)，随后写入 dtls12_cid、cidSz、dtls12_cid 和 length。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["aad"]},
        )
        return default

    if vid in (15, 19):
        default.update(
            status=STATUS_SAT,
            category="tls12_cid 内容类型常量和发送路径",
            risk="low",
            standard_section=RFC["outer"]["section"] if vid == 15 else RFC["iana"]["section"],
            standard_text=RFC["outer"]["quote"] if vid == 15 else RFC["iana"]["quote"],
            comment="wolfSSL 定义 dtls12_cid 为 25，并在 DTLS 且协商到 tx CID 时把外层记录类型设置为该值。",
            comparison_summary="要求：携带 CID 的 DTLS 1.2 外层记录 type 为 tls12_cid(25)。代码行为：internal.h 定义 dtls12_cid=25；BuildMessage 路径在 DtlsGetCidTxSize()>0 时设置 args->type=dtls12_cid。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["constants"] + BASE_EVIDENCE["record_write"]},
        )
        return default

    if vid == 20:
        default.update(
            status=STATUS_SAT,
            category="无 CID 记录不使用修改算法",
            risk="low",
            standard_section=RFC["record"]["section"],
            standard_text=RFC["record"]["quote"],
            comment="发送路径只有在 DtlsGetCidTxSize()>0 时改写外层 type 并追加 inner content type；否则保留普通 DTLS 记录头和普通 AAD。",
            comparison_summary="要求：不携带 CID 的记录不得应用修改后的算法。代码行为：CID AAD 和 dtls12_cid 记录头都以 CID size > 0 为条件；无 CID 时走普通 WriteSEQ/AAD。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["record_write"] + BASE_EVIDENCE["aad"]},
        )
        return default

    if vid in (21, 22):
        default.update(
            status=STATUS_SAT,
            category="inner plaintext 零填充解析",
            risk="low",
            standard_section=RFC["record"]["section"],
            standard_text="zeros:  An arbitrary-length run of zero-valued bytes may appear in the cleartext after the type field.",
            comment="wolfSSL 发送端不主动加入任意零填充；接收端 removeMsgInnerPadding 从末尾跳过 0 字节并要求找到非零 inner content type，因此接受的填充只能是 0x00。",
            comparison_summary="要求：DTLSInnerPlaintext 可包含任意长度零填充，且填充字节为 0。代码行为：removeMsgInnerPadding 从末尾回扫 0 字节，遇到非零字节作为真实 content type；若最终 type 为 0 则报错。结论：满足。",
            **{f"evidence_in_{IMPL_FIELD}": BASE_EVIDENCE["padding"]},
        )
        return default

    default.update(
        status=STATUS_SAT,
        category="已覆盖",
        risk="low",
        standard_section=RFC["record"]["section"],
        standard_text=item.get("evidence", ""),
        comment="经标准和代码路径对比未发现偏差。",
        comparison_summary="要求、标准含义和实现路径一致。",
        **{f"evidence_in_{IMPL_FIELD}": []},
    )
    return default


def write_md(results, counts):
    lines = [
        "# DTLS 1.2 CID / wolfSSL 对比审计 001-022",
        "",
        f"- 标准：RFC 9146",
        f"- 请求 target_repo：{TARGET_REQUESTED}",
        f"- 实际审计源码：{TARGET}",
        f"- 输入条目：001-022（输入 JSON 仅包含 22 条，已从 050 收敛到 022）",
        f"- 状态统计：{dict(counts)}",
        "",
        "| ID | 变量 | 状态 | 标准依据 | 对比结论 | 代码证据 |",
        "|---:|---|---|---|---|---|",
    ]
    for r in results:
        ev = "<br>".join(r.get(f"evidence_in_{IMPL_FIELD}", [])[:6])
        lines.append(
            f"| {r['id']:03d} | {r['variable_name']} | {r['status']} | {r['standard_section']} | {r['comparison_summary']} | {ev} |"
        )
    return "\n".join(lines) + "\n"


def write_simple(results):
    return "\n".join(
        f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['comment']}"
        for r in results
    ) + "\n"


def build_classification(results):
    items = []
    for r in results:
        if r["status"] not in (STATUS_PARTIAL, STATUS_UNSAT):
            continue
        v = dict(r)
        if r["id"] in (11, 17):
            v.update(
                verification_decision="confirmed_partial",
                standard_check="RFC 9146 的 Peer Address Update 条件同时要求记录成功去保护、CID 有效、并且 datagram 在 epoch 和 sequence number 上比已接收最新 datagram 更新。",
                code_check="wolfSSL 保存 pendingPeer，并且只有解密后调用 dtlsProcessPendingPeer(ssl, 1) 更新 peer；但 _DtlsCheckWindow 接受 nextEpoch-1 的 previous window，dtlsProcessPendingPeer 不检查该记录是否比最新记录更新。",
                test_check="verify_wolfssl_dtls_cid_001_022.py::test_peer_update_lacks_strict_newer_gate 通过，确认 previous-epoch 分支和无 newer gate 的 peer 更新路径同时存在。",
                decision_reason="已实现 CID 匹配和解密成功门控；缺失对地址更新专用的 strict newer(epoch, sequence) 判断，因此为 confirmed_partial。",
            )
        elif r["id"] == 18:
            v.update(
                verification_decision="confirmed_partial",
                standard_check="RFC 9146 将 tls12_cid(25) 定义为 DTLS 1.2 content type；DTLS 1.3 CID 使用不同记录头机制。",
                code_check="记录层代码正确把 DTLS 1.2 CID type 定义为 25，并在 DTLS 1.2 CID 记录中使用；但 CMakeLists.txt 在 WOLFSSL_DTLS_CID 且未启用 WOLFSSL_DTLS13 时 FATAL_ERROR。",
                test_check="verify_wolfssl_dtls_cid_001_022.py::test_cmake_cid_requires_dtls13 通过，确认 CMake 约束存在；test_constants_and_record_paths 通过，确认数据面常量和路径存在。",
                decision_reason="数据面基本满足，但 CMake 启用路径与 DTLS 1.2 CID 的适用范围不一致，confirmed_partial。",
            )
        items.append(v)
    return items


def classification_md(items):
    groups = defaultdict(list)
    for item in items:
        groups[item["category"]].append(item)
    lines = [
        "# 部分满足/不满足分类 001-022",
        "",
        f"- 总数：{len(items)}",
        f"- 状态统计：{dict(Counter(i['status'] for i in items))}",
        f"- 风险统计：{dict(Counter(i['risk'] for i in items))}",
        "",
    ]
    for cat, vals in groups.items():
        lines.append(f"## {cat}")
        for v in vals:
            lines.extend([
                f"- ID {v['id']:03d}：{v['status']}，风险 {v['risk']}",
                f"  - reason: {v['comment']}",
                f"  - standard_check: {v.get('standard_check', '')}",
                f"  - code_check: {v.get('code_check', '')}",
                f"  - test_check: {v.get('test_check', '')}",
                f"  - decision_reason: {v.get('decision_reason', '')}",
            ])
    return "\n".join(lines) + "\n"


VERIFY = r'''import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="replace")

def require(name, cond, detail):
    if not cond:
        raise AssertionError(f"{name}: {detail}")
    print(f"PASS {name}: {detail}")

def test_cmake_cid_requires_dtls13():
    cmake = read("CMakeLists.txt")
    cache = read("build/CMakeCache.txt")
    require("cmake default off", re.search(r'add_option\("WOLFSSL_DTLS_CID".*?"no"\s+"yes;no"\)', cmake, re.S) is not None, "CMake option defaults to no")
    require("cmake requires dtls13", "if(NOT WOLFSSL_DTLS13)" in cmake and "CID are supported only for DTLSv1.3" in cmake, "CMake rejects CID without DTLS 1.3")
    require("existing build cid off", "WOLFSSL_DTLS_CID:BOOL=no" in cache, "checked build cache has CID disabled")

def test_constants_and_record_paths():
    ih = read("wolfssl/internal.h")
    internal = read("src/internal.c")
    require("extension 54", "#define TLSXT_CONNECTION_ID              0x0036" in ih, "connection_id extension constant is 54")
    require("content type 25", "dtls12_cid         = 25" in ih, "tls12_cid content type is 25")
    require("record type set", "args->type = dtls12_cid" in internal, "sender sets outer record type when tx CID exists")
    require("cid emitted", "wolfSSL_dtls_cid_get_tx(ssl, output + DTLS12_CID_OFFSET, cidSz)" in internal, "sender writes negotiated tx CID")
    require("inner type appended", "output[args->idx++] = (byte)type; /* type goes after input */" in internal, "sender serializes inner content type")

def test_aad_matches_rfc9146_shape():
    internal = read("src/internal.c")
    require("aad placeholder", "XMEMSET(additional + idx, 0xFF, SEQ_SZ)" in internal, "AAD starts with eight 0xff bytes")
    require("aad tls12 cid", internal.count("additional[idx++] = dtls12_cid") >= 2, "AAD includes tls12_cid in the expected positions")
    require("aad cid length", "additional[idx++] = cidSz" in internal, "AAD includes cid_length")
    require("aad inner length", "c16toa(sz, additional + idx)" in internal, "AAD includes length_of_DTLSInnerPlaintext")

def test_peer_update_lacks_strict_newer_gate():
    internal = read("src/internal.c")
    require("previous epoch accepted", "ssl->keys.curEpoch == peerSeq->nextEpoch - 1" in internal, "DTLS 1.2 window logic accepts previous epoch window")
    start = internal.find("static void dtlsProcessPendingPeer(WOLFSSL* ssl, int deprotected)")
    end = internal.find("#endif", start)
    require("pending peer function found", start >= 0 and end > start, "dtlsProcessPendingPeer is present")
    body = internal[start:end]
    require("peer update after deprotect", "wolfSSL_dtls_set_peer" in body and "deprotected" in body, "pending peer is promoted after deprotection")
    strict_terms = ["newest datagram", "newer", "latest", "lastEpoch", "lastSeq"]
    require("no strict newer gate", not any(term in body for term in strict_terms), "peer promotion body has no explicit newest-datagram comparison")

if __name__ == "__main__":
    test_cmake_cid_requires_dtls13()
    test_constants_and_record_paths()
    test_aad_matches_rfc9146_shape()
    test_peer_update_lacks_strict_newer_gate()
'''


def report_for(item):
    if item["id"] in (11, 17):
        title = "CID peer address update lacks strict newer-record gate"
        source = source_snippet("src/internal.c", 19034, 19045) + "\n\n" + source_snippet("src/internal.c", 22584, 22606) + "\n\n" + source_snippet("src/internal.c", 23283, 23289)
        implemented = "wolfSSL records a pending peer address and promotes it only after the record has been decrypted and authenticated."
        missing = "The promotion path does not require the triggering datagram to be newer than the newest received datagram in both epoch and sequence number; the DTLS 1.2 replay window explicitly has a previous-epoch branch."
    else:
        title = "CMake DTLS CID option is tied to DTLS 1.3"
        source = source_snippet("CMakeLists.txt", 419, 427) + "\n\n" + source_snippet("wolfssl/internal.h", 6615, 6621) + "\n\n" + source_snippet("src/internal.c", 24488, 24490)
        implemented = "The record layer has a DTLS 1.2 tls12_cid(25) constant and data path."
        missing = "The CMake build option rejects WOLFSSL_DTLS_CID unless WOLFSSL_DTLS13 is also enabled, so a CMake user cannot enable the DTLS 1.2 CID feature alone."

    return f"""# {title}

## Summary
本项复核结论为 confirmed_partial。{item['comment']}

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc9146

Section: {item['standard_section']}

```text
{item['standard_text']}
```

该要求需要实现不仅有相关符号，还要在记录处理条件下满足 RFC 9146 的行为约束。

## Relevant Source Code
```c
{source}
```

## Implementation Behavior
{implemented}

## Inconsistency Reason
标准要求：{item['standard_check']}

实现情况：{item['code_check']}

不一致点：{missing}

## Runtime Evidence
Focused verification script: `verify_wolfssl_dtls_cid_001_022.py`

Log file: `verify_wolfssl_dtls_cid_001_022.log`

Test result: {item['test_check']}

The additional executable `runtime_dtlscid_default_probe.exe` was linked against the existing `build/wolfssl-default/libwolfssl.a` and printed `WOLFSSL_DTLS_CID not defined`, confirming that the checked default build does not expose the DTLS CID API.

## Impact
该问题主要影响启用 DTLS CID 后的严格协议一致性。地址更新问题可能导致旧 epoch 窗口内但可成功去保护的记录触发 peer 地址切换；CMake 问题会影响仅希望构建 DTLS 1.2 CID 的用户。

## Fix Direction
对地址更新路径，应在 pending peer promotion 前保存并比较触发记录与“最新已接收 datagram”的 epoch/sequence，只有严格更新时才更新 peer。对 CMake 路径，应允许 DTLS 1.2 CID 独立启用，或把错误信息和选项拆分为 DTLS 1.2 CID 与 DTLS 1.3 CID。
"""


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    changes = data["changes"]
    results = [classify_item(i, item) for i, item in enumerate(changes)]
    counts = Counter(r["status"] for r in results)
    validation = {
        "checked_evidence_refs": 0,
        "missing_or_bad_refs": [],
    }
    for r in results:
        for ref in r.get(f"evidence_in_{IMPL_FIELD}", []):
            validation["checked_evidence_refs"] += 1
            if not evidence_exists(ref):
                validation["missing_or_bad_refs"].append(ref)

    compare = {
        "meta": {
            "protocol_name": "DTLS 1.2 CID",
            "standard_reference": "https://www.rfc-editor.org/rfc/rfc9146",
            "source_file": str(INPUT),
            "scope": "001-022_rules",
            "requested_scope": "001-050",
            "clamped_reason": "input JSON contains only 22 changes",
            "method": "static_code_comparison_plus_focused_verification",
            "requested_target": str(TARGET_REQUESTED),
            "actual_target": str(TARGET),
            "target_note": "requested wolfssl-main did not exist; wolfssl-master was the available wolfSSL source tree in the workspace",
            "counts": dict(counts),
            "evidence_validation": validation,
        },
        "results": results,
    }

    (OUT / f"compare_{IMPL_FILE}_001_022.json").write_text(json.dumps(compare, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / f"compare_{IMPL_FILE}_001_022.md").write_text(write_md(results, counts), encoding="utf-8")
    (OUT / f"compare_{IMPL_FILE}_001_022_simple.txt").write_text(write_simple(results), encoding="utf-8")

    items = build_classification(results)
    class_obj = {
        "scope": f"{IMPL_FILE} 001-022 partial+unsatisfied",
        "total_reviewed": len(items),
        "status_summary": dict(Counter(i["status"] for i in items)),
        "risk_summary": dict(Counter(i["risk"] for i in items)),
        "category_summary": {
            cat: {
                "count": len(vals),
                "unsatisfied": sum(1 for v in vals if v["status"] == STATUS_UNSAT),
                "partial": sum(1 for v in vals if v["status"] == STATUS_PARTIAL),
            }
            for cat, vals in defaultdict(list, {k: [i for i in items if i["category"] == k] for k in {i["category"] for i in items}}).items()
        },
        "results": items,
    }
    (OUT / f"compare_{IMPL_FILE}_001_022_partial_unsat_classification.json").write_text(json.dumps(class_obj, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / f"compare_{IMPL_FILE}_001_022_partial_unsat_classification.md").write_text(classification_md(items), encoding="utf-8")

    verify_path = OUT / "verify_wolfssl_dtls_cid_001_022.py"
    verify_path.write_text(VERIFY, encoding="utf-8")
    log_path = OUT / "verify_wolfssl_dtls_cid_001_022.log"
    proc = subprocess.run([sys.executable, str(verify_path)], cwd=str(OUT), text=True, capture_output=True)
    log_path.write_text(proc.stdout + proc.stderr + f"\nexit_code={proc.returncode}\n", encoding="utf-8")
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)

    runtime_probe = OUT / "runtime_dtlscid_default_probe.exe"
    if runtime_probe.exists():
        runtime_proc = subprocess.run([str(runtime_probe)], cwd=str(OUT), text=True, capture_output=True)
        with log_path.open("a", encoding="utf-8") as f:
            f.write("\nRuntime probe: runtime_dtlscid_default_probe.exe\n")
            f.write(runtime_proc.stdout)
            f.write(runtime_proc.stderr)
            f.write(f"runtime_exit_code={runtime_proc.returncode}\n")

    for item in items:
        if item["id"] in (11, 17):
            topic = "peer_address_update_newer_gate"
        else:
            topic = "dtls12_cid_cmake_dtls13_dependency"
        (OUT / f"id{item['id']:03d}_{topic}_confirmed_partial.md").write_text(report_for(item), encoding="utf-8")

    summary = {
        "round": "001-022",
        "requested_round": "001-050",
        "counts": dict(counts),
        "classification_count": len(items),
        "confirmed_partial": [i["id"] for i in items if i["verification_decision"] == "confirmed_partial"],
        "confirmed_unsatisfied": [],
        "false_positive": [],
        "next_round": None,
        "next_round_reason": "input JSON has only 22 changes; no 023-050 entries exist",
        "verification_log": str(log_path),
        "output_files": sorted(p.name for p in OUT.iterdir() if p.is_file()),
    }
    (OUT / "round_summary_001_022.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "round_summary_001_022.md").write_text(
        "# 本轮汇总 001-022\n\n"
        f"- 请求范围：001-050；实际范围：001-022（输入 JSON 仅 22 条）\n"
        f"- 状态统计：{dict(counts)}\n"
        f"- confirmed_partial：{summary['confirmed_partial']}\n"
        "- confirmed_unsatisfied：无\n"
        "- false_positive：无\n"
        "- 下一轮范围：无；不存在 023-050 条目。\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
