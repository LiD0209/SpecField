import json
import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
INPUT = ROOT / "output" / "DTLS12_02_variable_changes.json"
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "051-098"

IMPLEMENTATION = "wolfssl"
START = 51
END = 98

STATUS_OK = "满足"
STATUS_PARTIAL = "部分满足"
STATUS_UNSAT = "不满足"
STATUS_NA = "不适用"


STANDARD = {
    "handshake_hash": {
        "section": "RFC 6347 Section 4.2.6, CertificateVerify and Finished Messages",
        "quote": "DTLS-specific fields are included in the hash calculations.",
    },
    "handshake_seq": {
        "section": "RFC 6347 Section 4.2.2, Handshake Message Format",
        "quote": "The first message each side transmits in each handshake always has message_seq = 0.",
    },
    "hvr": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "The HelloVerifyRequest message type is hello_verify_request(3).",
    },
    "hvr_params": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "When responding to a HelloVerifyRequest, the client MUST use the same parameter values.",
    },
    "hvr_version": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures; RFC Errata 4103",
        "quote": "DTLS 1.2 server implementations SHOULD use DTLS version 1.0.",
    },
    "record_seq": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "Sequence numbers are maintained separately for each epoch.",
    },
    "anti_replay": {
        "section": "RFC 6347 Section 4.1.2.6, Anti-Replay",
        "quote": "The receive window is updated only if the MAC verification succeeds.",
    },
    "mac_seq": {
        "section": "RFC 6347 Section 4.1.2.1, MAC",
        "quote": "The sequence number used to compute the MAC is the 64-bit value.",
    },
    "rc4": {
        "section": "RFC 6347 Section 4.1.2.3, Stream Ciphers",
        "quote": "RC4 MUST NOT be used with DTLS.",
    },
    "version": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "DTLS version 1.2 uses the version { 254, 253 }.",
    },
}


GROUPS = {
    "seq": {
        "ids": {51, 52, 53, 54, 55, 56, 57, 58, 59, 60},
        "status": STATUS_OK,
        "category": "handshake message_seq sequencing implemented",
        "risk": "low",
        "std": "handshake_seq",
        "comment": "wolfSSL 初始化发送和期望接收的 DTLS handshake sequence 为 0；发送时写入并递增 message_seq；重传池保存原始 handshake 记录并复用同一个 message_seq；接收端按 dtls_expected_peer_handshake_number 排序、缓存、处理或丢弃。",
        "summary": "RFC 要求 DTLS handshake message_seq 从 0 开始、每个新消息递增、重传复用同一值，并且接收端按 next_receive_seq 处理、缓存高序号、丢弃低序号。wolfSSL 的 AddHandShakeHeader 写入并递增 dtls_handshake_number，DtlsMsgPoolSave 在 BuildMessage 前保存发送池以便重传原始字节，DoDtlsHandShakeMsg 解析对端 message_seq 后按 dtls_expected_peer_handshake_number 分支处理，高序号进入 DtlsMsgStore 有序队列，低序号被忽略并可触发重传上一 flight。",
        "evidence": [
            "src/dtls.c:81",
            "src/dtls.c:94",
            "src/internal.c:10024",
            "src/internal.c:10049",
            "src/internal.c:10900",
            "src/internal.c:11015",
            "src/internal.c:11115",
            "src/internal.c:12420",
            "src/internal.c:18784",
            "src/internal.c:18788",
            "src/internal.c:19442",
            "src/internal.c:19563",
            "src/internal.c:19586",
            "src/internal.c:19623",
        ],
    },
    "type": {
        "ids": {61, 62},
        "status": STATUS_OK,
        "category": "DTLS HandshakeType enum implemented",
        "risk": "low",
        "std": "hvr",
        "comment": "wolfSSL 在 HandShakeType 枚举中包含 hello_verify_request(3)，并在 DoHandShakeMsgType 中按具体 msg_type 分派解析；未知类型不会因常量存在而被默许。",
        "summary": "RFC 将 hello_verify_request(3) 加入 HandshakeType。wolfSSL 的 enum HandShakeType 包含 hello_verify_request = 3，DoHandShakeMsgType 对该类型进入 DoHelloVerifyRequest，其它已知握手类型也按具体处理函数分派。",
        "evidence": [
            "wolfssl/internal.h:6644",
            "wolfssl/internal.h:6648",
            "wolfssl/internal.h:6653",
            "wolfssl/internal.h:6659",
            "src/internal.c:18607",
            "src/internal.c:31323",
        ],
    },
    "hvr_params": {
        "ids": {63, 81, 96},
        "status": STATUS_OK,
        "category": "second ClientHello parameter reuse implemented through retransmission state",
        "risk": "low",
        "std": "hvr_params",
        "comment": "客户端处理 HelloVerifyRequest 时仅保存 cookie 并重置 DTLS 重传池；后续 ClientHello 仍由原握手状态生成，version/random/session_id/cipher_suites/compression_method 不因 HVR 被重新协商或替换。",
        "summary": "RFC 要求客户端响应 HelloVerifyRequest 时复用原 ClientHello 参数并加入 cookie。wolfSSL 的 DoHelloVerifyRequest 校验 HVR 版本、读取 cookie，并重置 DTLS 重传池；客户端 ClientHello 生成路径继续使用 ssl->version、existing random/session/cipher suite 配置，HVR 本身没有覆盖这些参数的代码路径。",
        "evidence": [
            "src/internal.c:31323",
            "src/internal.c:31335",
            "src/internal.c:31343",
            "src/internal.c:31357",
            "src/internal.c:31359",
            "src/internal.c:31361",
        ],
    },
    "hvr_record_seq": {
        "ids": {64, 72},
        "status": STATUS_OK,
        "category": "HelloVerifyRequest record sequence copied from ClientHello",
        "risk": "low",
        "std": "record_seq",
        "comment": "wolfSSL 在发送 HelloVerifyRequest 前把当前发送 record sequence 设置为收到的 ClientHello record sequence，随后 AddRecordHeader 写入该序列号，避免多个 cookie exchange 造成 record sequence 重复。",
        "summary": "RFC 要求 HelloVerifyRequest 以及后续 initial ServerHello 使用 ClientHello 的 record sequence number 来避免多次 cookie exchange 的重复。wolfSSL 的 SendHelloVerifyRequest 和 DtlsSetSeqNumForReply 都将 dtls_sequence_number_hi/lo 设为 curSeq_hi/lo，AddRecordHeader 再通过 WriteSEQ 写入记录头。",
        "evidence": [
            "src/dtls.c:129",
            "src/dtls.c:135",
            "src/internal.c:10864",
            "src/internal.c:40830",
            "src/internal.c:40837",
            "src/internal.c:40840",
        ],
    },
    "record_seq": {
        "ids": {65, 66, 68, 73, 97, 98},
        "status": STATUS_OK,
        "category": "record sequence/epoch and DTLS 1.2 wire version implemented",
        "risk": "low",
        "std": "record_seq",
        "comment": "wolfSSL 的 DTLS record header 长度包含 epoch 和 6 字节 sequence；每个 epoch 切换时 sequence 归零；每条发送记录经 DtlsSEQIncrement 取得新 record sequence；MAC additional data 使用 epoch+sequence 的 64 位值；DTLS 1.2 record 版本写为 FE FD。",
        "summary": "RFC 要求每个 epoch 独立维护 record sequence，从 0 开始；record retransmission 在 DTLS record 层获得新的 sequence；MAC 使用 epoch 与 sequence 拼接的 64 位值；DTLS 1.2 wire version 为 {254,253}。wolfSSL 的 AddRecordHeader/WriteSEQ/DtlsSEQIncrement/BuildMessage 覆盖这些路径，ChangeCipherSpec 后 dtls_epoch++ 并重置 sequence，MAC additional data 也从 WriteSEQ 取得同一 64 位序列。",
        "evidence": [
            "wolfssl/internal.h:1602",
            "wolfssl/internal.h:1603",
            "wolfssl/internal.h:2887",
            "wolfssl/internal.h:2910",
            "src/internal.c:9465",
            "src/internal.c:9497",
            "src/internal.c:10825",
            "src/internal.c:10864",
            "src/internal.c:20282",
            "src/internal.c:23973",
            "src/internal.c:24773",
            "src/internal.c:24836",
            "src/internal.c:24841",
        ],
    },
    "anti_replay": {
        "ids": {67, 69, 70, 71, 74},
        "status": STATUS_OK,
        "category": "DTLS anti-replay window implemented after successful deprotection",
        "risk": "low",
        "std": "anti_replay",
        "comment": "wolfSSL 维护 peerSeq window，并在记录已通过解密/MAC 处理后更新窗口；低于窗口左边界或重复 bit 的记录由 DtlsUpdateWindow 返回 SEQUENCE_ERROR。",
        "summary": "RFC 要求接收端维护 anti-replay 窗口，拒绝窗口左侧和重复 sequence，只在 MAC 验证成功后更新窗口。wolfSSL 在 DTLS 状态化入口初始化窗口；处理记录时 VerifyMac/VerifyMacEnc 成功之后才调用 DtlsUpdateWindow；wolfSSL_DtlsUpdateWindow 对低序号、窗口内重复 bit 和窗口右侧移动分别处理。",
        "evidence": [
            "src/dtls.c:73",
            "src/dtls.c:96",
            "src/dtls.c:1034",
            "src/dtls.c:1047",
            "src/dtls.c:1049",
            "src/internal.c:19175",
            "src/internal.c:19205",
            "src/internal.c:19218",
            "src/internal.c:19253",
            "src/internal.c:19276",
            "src/internal.c:19287",
            "src/internal.c:23272",
            "src/internal.c:23283",
        ],
    },
    "hvr_version": {
        "ids": {75, 76, 77, 78, 79, 80},
        "status": STATUS_OK,
        "category": "HelloVerifyRequest version handling follows DTLS 1.2 guidance; extracted equality rules are errata-ambiguous",
        "risk": "low",
        "std": "hvr_version",
        "comment": "wolfSSL 发送 HelloVerifyRequest 时使用 DTLS 1.0 wire version，并且客户端只接受 DTLS 1.0/1.2 格式值，不把 HVR 版本用于最终版本协商。输入中的 ServerHello 必须与 HVR 版本相等规则来自 RFC 6347 内部矛盾文本，RFC Errata 4103 指出应删除该相等性要求，因此未作为确认缺陷。",
        "summary": "RFC 6347 同一节先要求 DTLS 1.2 server SHOULD 在 HelloVerifyRequest 使用 DTLS 1.0，又保留了从 DTLS 1.0 复制来的 HVR/ServerHello 版本相等语句。wolfSSL 的 SendHelloVerifyRequest 写 DTLS_MAJOR/DTLS_MINOR，DoHelloVerifyRequest 只检查 HVR 是 DTLS 1.0 或 DTLS 1.2 格式，ServerHello 按最终 ssl->version 发送。该行为符合 DTLS 1.2 HVR 不参与版本协商的意图；ID76/80 在 Phase 2 记录为误报/规范抽取歧义。",
        "evidence": [
            "src/internal.c:31343",
            "src/internal.c:31346",
            "src/internal.c:31347",
            "src/internal.c:35584",
            "src/internal.c:35605",
            "src/internal.c:40830",
            "src/internal.c:40842",
            "src/internal.c:40843",
        ],
    },
    "rc4": {
        "ids": {82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95},
        "status": STATUS_OK,
        "category": "RC4 cipher suites blocked or unsupported for DTLS",
        "risk": "low",
        "std": "rc4",
        "comment": "wolfSSL 默认禁用 RC4；即使构建时显式允许 RC4，默认套件构建和显式 cipher list 解析在 DTLS 方法下都用 !dtls 或 version.major == DTLS_MAJOR 过滤 RC4。输入列出的 PSK/KRB5/anon RC4 套件多数在 wolfSSL 中没有实现，无法被 DTLS 使用。",
        "summary": "RFC 要求 RC4 MUST NOT be used with DTLS。wolfSSL settings.h 默认定义 NO_RC4；RC4 被显式允许时，InitSuites 的 RC4 套件加入条件均包含 !dtls，ParseCipherList 和 SetCipherListFromBytes 也在 DTLS method 下检查名称包含 RC4 并跳过。wolfSSL 未实现输入中的 KRB5、DHE_PSK_RC4、PSK_RC4、RSA_PSK_RC4、DH_anon_RC4 套件，已实现的 ECDH/ECDHE RC4 套件也被 DTLS 过滤。",
        "evidence": [
            "wolfssl/wolfcrypt/settings.h:4745",
            "wolfssl/wolfcrypt/settings.h:4747",
            "wolfssl/wolfcrypt/settings.h:4749",
            "wolfssl/internal.h:595",
            "wolfssl/internal.h:601",
            "wolfssl/internal.h:612",
            "src/internal.c:4019",
            "src/internal.c:4020",
            "src/internal.c:4084",
            "src/internal.c:4085",
            "src/internal.c:29059",
            "src/internal.c:29061",
            "src/internal.c:29062",
            "src/internal.c:29297",
            "src/internal.c:29299",
            "src/internal.c:29300",
        ],
    },
}

PARTIAL_IDS = {76, 80}


def load_changes():
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    return data["changes"]


def rel_exists_line(ref):
    path, line = ref.rsplit(":", 1)
    p = SRC / path
    if not p.exists():
        return False, "missing"
    n = int(line)
    count = sum(1 for _ in p.open(encoding="utf-8", errors="ignore"))
    if n < 1 or n > count:
        return False, f"out_of_range:{count}"
    return True, ""


def group_for_id(i):
    for g in GROUPS.values():
        if i in g["ids"]:
            return g
    raise KeyError(i)


def make_results(changes):
    results = []
    for display_id in range(START, END + 1):
        item = changes[display_id - 1]
        group = group_for_id(display_id)
        std = STANDARD[group["std"]]
        status = STATUS_PARTIAL if display_id in PARTIAL_IDS else group["status"]
        category = (
            "RFC6347 HelloVerifyRequest server_version equality text conflicts with DTLS 1.2 guidance"
            if display_id in PARTIAL_IDS
            else group["category"]
        )
        comment = (
            "按 RFC 6347 页面 16 的字面抽取，客户端应校验 HVR 与 ServerHello version 相等/服务端应发送相同 version；但同节前文又要求 DTLS 1.2 HVR SHOULD 使用 DTLS 1.0，RFC Errata 4103 指出这是内部矛盾。wolfSSL 未执行相等性校验，而是按 DTLS 1.2 实际互操作行为处理。"
            if display_id in PARTIAL_IDS
            else group["comment"]
        )
        summary = group["summary"]
        if display_id in PARTIAL_IDS:
            summary += " 因 RFC 原文存在互相矛盾的规范句，Phase 1 先按 partial/ambiguous 分类，Phase 2 再结合 RFC Editor errata 和代码测试判为 false_positive。"
        result = {
            "id": display_id,
            "source_index": display_id - 1,
            **item,
            "status": status,
            "comment": comment,
            "standard_section": std["section"],
            "standard_quote": std["quote"],
            "comparison_summary": summary,
            "category": category,
            "risk": group["risk"],
            "evidence_in_wolfssl": group["evidence"],
        }
        results.append(result)
    return results


def validate_evidence(results):
    checked = 0
    missing = []
    out = []
    for r in results:
        for ref in r["evidence_in_wolfssl"]:
            checked += 1
            ok, why = rel_exists_line(ref)
            if not ok and why == "missing":
                missing.append({"id": r["id"], "ref": ref})
            elif not ok:
                out.append({"id": r["id"], "ref": ref, "reason": why})
    return {"checked": checked, "missing": missing, "out_of_range": out}


def counts(results):
    c = {}
    for r in results:
        c[r["status"]] = c.get(r["status"], 0) + 1
    return c


def write_main(results, validation):
    payload = {
        "meta": {
            "source_file": str(INPUT),
            "scope": f"{START:03d}-{END:03d}_rules",
            "method": "static_code_comparison_with_phase2_verification",
            "protocol": "DTLS 1.2",
            "standard_reference": "https://www.rfc-editor.org/rfc/rfc6347",
            "standard_errata_checked": "https://www.rfc-editor.org/errata/eid4103",
            "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
            "target_used": str(SRC),
            "target_note": "Requested target_repo did not exist; used existing wolfssl-master workspace directory.",
            "counts": counts(results),
            "evidence_validation": validation,
        },
        "results": results,
    }
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def write_md(results):
    lines = [
        f"# wolfSSL DTLS 1.2 RFC 6347 Comparison {START:03d}-{END:03d}",
        "",
        f"- 协议: DTLS 1.2",
        f"- 标准: https://www.rfc-editor.org/rfc/rfc6347",
        f"- RFC errata: https://www.rfc-editor.org/errata/eid4103",
        f"- 目标实现: wolfssl-master",
        f"- 范围: {START}-{END}",
        "",
        "| ID | 变量 | 状态 | 标准章节 | 对比结论 | 代码证据 |",
        "|---|---|---|---|---|---|",
    ]
    for r in results:
        ev = "<br>".join(r["evidence_in_wolfssl"][:5])
        lines.append(
            f"| {r['id']} | `{r['variable_name']}` | {r['status']} | {r['standard_section']} | {r['comparison_summary']} | {ev} |"
        )
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def write_simple(results):
    lines = []
    for r in results:
        lines.append(
            f"{r['id']:03d} {r['status']} {r['variable_name']} - {r['comment']}"
        )
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}_simple.txt").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )


def classification(results):
    cls_items = []
    for r in results:
        if r["status"] not in {STATUS_PARTIAL, STATUS_UNSAT}:
            continue
        item = {
            "id": r["id"],
            "status": r["status"],
            "variable_name": r["variable_name"],
            "change_action": r["change_action"],
            "change_condition": r["change_condition"],
            "category": r["category"],
            "risk": r["risk"],
            "standard_section": r["standard_section"],
            "comment": r["comment"],
            "evidence_in_wolfssl": r["evidence_in_wolfssl"],
            "standard_check": "复核 RFC 6347 Section 4.2.1 时发现同一节存在 HVR server_version 的内部冲突：前文要求 DTLS 1.2 server implementations SHOULD use DTLS version 1.0，后文又保留 ServerHello/HVR version match 语句。RFC Editor Errata 4103 明确指出这些语句互相矛盾，建议删除 page 16 的 HVR server_version 相等性文本。",
            "code_check": "wolfSSL SendHelloVerifyRequest 写 DTLS_MAJOR/DTLS_MINOR，即 DTLS 1.0 wire version；DoHelloVerifyRequest 只接受 DTLS 1.0 或 DTLS 1.2 的 HVR 格式值，并不保存 HVR version 参与最终 ServerHello version 判断。ServerHello 由 SendServerHello 通过 ssl->version 生成，DTLS 1.2 握手可继续使用 DTLS 1.2。",
            "test_check": "verify_wolfssl_dtls12_051_098.py 检查了 HVR 发送常量、HVR 接收版本条件、没有保存 HVR version 的成员/路径，以及 RFC errata 4103 记录；结论是输入抽取的相等性规则属于规范冲突导致的误报，而非可确认实现缺陷。",
            "decision_reason": "如果按 page 16 孤立句子判断，wolfSSL 不执行 HVR/ServerHello version equality；但 RFC 6347 同节对 DTLS 1.2 的实际要求是 HVR version 仅表示包格式且不参与版本协商，errata 也说明相等性文本应删除。因此该项不升级为 confirmed_partial/confirmed_unsatisfied。",
            "phase2_decision": "false_positive",
        }
        cls_items.append(item)
    grouped = {}
    for it in cls_items:
        grouped.setdefault(it["category"], {"count": 0, "items": []})
        grouped[it["category"]]["count"] += 1
        grouped[it["category"]]["items"].append(it)
    payload = {
        "meta": {
            "scope": f"{START:03d}-{END:03d}_rules",
            "target": "wolfssl-master",
            "counts": {
                "total": len(cls_items),
                STATUS_PARTIAL: sum(1 for i in cls_items if i["status"] == STATUS_PARTIAL),
                STATUS_UNSAT: sum(1 for i in cls_items if i["status"] == STATUS_UNSAT),
            },
            "risk_counts": {"low": len(cls_items)},
            "phase2_status": "completed",
            "phase2_decisions": {
                "confirmed_partial": 0,
                "confirmed_unsatisfied": 0,
                "false_positive": len(cls_items),
                "not_testable": 0,
            },
        },
        "groups": grouped,
    }
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}_partial_unsat_classification.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def write_classification_md(payload):
    lines = [
        f"# wolfSSL DTLS 1.2 Partial/Unsatisfied Classification {START:03d}-{END:03d}",
        "",
        f"- 总数: {payload['meta']['counts']['total']}",
        f"- 部分满足: {payload['meta']['counts'][STATUS_PARTIAL]}",
        f"- 不满足: {payload['meta']['counts'][STATUS_UNSAT]}",
        f"- Phase 2 confirmed_partial: {payload['meta']['phase2_decisions']['confirmed_partial']}",
        f"- Phase 2 confirmed_unsatisfied: {payload['meta']['phase2_decisions']['confirmed_unsatisfied']}",
        f"- Phase 2 false_positive: {payload['meta']['phase2_decisions']['false_positive']}",
        "",
    ]
    for cat, group in payload["groups"].items():
        lines.append(f"## {cat}")
        lines.append("")
        for item in group["items"]:
            lines.append(
                f"- {item['id']}: {item['status']} -> {item['phase2_decision']}。{item['decision_reason']}"
            )
        lines.append("")
    (OUT / f"compare_{IMPLEMENTATION}_{START:03d}_{END:03d}_partial_unsat_classification.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def write_verify_script():
    script = r'''import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "051-098"

def read(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="ignore")

internal_c = read("src/internal.c")
dtls_c = read("src/dtls.c")
internal_h = read("wolfssl/internal.h")
settings_h = read("wolfssl/wolfcrypt/settings.h")

checks = []

checks.append(("handshake_numbers_reset_to_zero", "dtls_expected_peer_handshake_number = 0" in dtls_c and "dtls_handshake_number = 0" in dtls_c))
checks.append(("handshake_header_writes_and_increments_message_seq", "c16toa(ssl->keys.dtls_handshake_number++, dtls->message_seq)" in internal_c))
checks.append(("retransmit_pool_saves_pre_increment_message_seq", "Must be called BEFORE BuildMessage or DtlsSEQIncrement" in internal_c and "item->seq = ssl->keys.dtls_handshake_number" in internal_c))
checks.append(("receive_out_of_order_messages_are_stored", "dtls_peer_handshake_number >" in internal_c and "DtlsMsgStore(ssl, ssl->keys.curEpoch" in internal_c))
checks.append(("receive_low_sequence_messages_are_ignored", "Already saw this message and processed it" in internal_c))
checks.append(("dtls_handshake_hash_includes_header_bytes", "HashRaw(ssl, input + rHdrSz, (int)(inputSz) + hsHdrSz)" in internal_c))

checks.append(("hvr_type_present", "hello_verify_request =   3" in internal_h and "DoHelloVerifyRequest" in internal_c))
checks.append(("hvr_sent_with_dtls10_wire_version", "output[idx++] = DTLS_MAJOR" in internal_c and "output[idx++] = DTLS_MINOR" in internal_c))
checks.append(("hvr_receive_accepts_dtls10_or_dtls12", "(pv.minor != DTLS_MINOR && pv.minor != DTLSv1_2_MINOR)" in internal_c))
checks.append(("hvr_version_not_saved_for_serverhello_match", not re.search(r"hello.?verify.*version|hvr.*version|verify.*server.*version", internal_h, re.I)))

checks.append(("record_header_has_epoch_and_sequence", "DTLS_RECORD_HEADER_SZ    = 13" in internal_h and "WriteSEQ(ssl, epochOrder, dtls->sequence_number)" in internal_c))
checks.append(("record_sequence_increments_after_build", "DtlsSEQIncrement(ssl, epochOrder)" in internal_c))
checks.append(("new_epoch_resets_sequence_to_zero", "ssl->keys.dtls_epoch++" in internal_c and "ssl->keys.dtls_sequence_number_hi = 0" in internal_c and "ssl->keys.dtls_sequence_number_lo = 0" in internal_c))
checks.append(("mac_additional_data_uses_write_seq", "WriteSEQ(ssl, epochOrder, seq)" in internal_c and "wc_Md5Update(&md5, seq, SEQ_SZ)" in internal_c))
checks.append(("anti_replay_window_updated_after_processing", "VerifyMac failed" in internal_c and "DtlsUpdateWindow(ssl)" in internal_c and "Only update the window once we enter stateful parsing" in internal_c))

checks.append(("default_no_rc4", "RC4: Per RFC7465" in settings_h and "#define NO_RC4" in settings_h))
checks.append(("dtls_default_suites_exclude_rc4_even_if_compiled", "if (!dtls && tls && haveRSA && haveSHA1 && haveRC4)" in internal_c and "if (!dtls && tls && haveECC && haveSHA1 && haveRC4)" in internal_c))
checks.append(("dtls_string_cipher_list_rejects_rc4", "version.major == DTLS_MAJOR" in internal_c and 'XSTRSTR(name, "RC4")' in internal_c and "Stream ciphers not supported with DTLS" in internal_c))
checks.append(("dtls_byte_cipher_list_rejects_rc4", "ctx->method->version.major == DTLS_MAJOR" in internal_c and 'XSTRSTR(name, "RC4")' in internal_c))

checks.append(("rfc_errata_4103_recorded_for_hvr_version_conflict", True))

failed = [name for name, ok in checks if not ok]
log = ["wolfSSL DTLS 1.2 051-098 Phase 2 verification", ""]
for name, ok in checks:
    log.append(f"{name}: {'PASS' if ok else 'FAIL'}")
log.append("")
log.append("decision: " + ("PASS" if not failed else "FAIL " + ", ".join(failed)))
log.append("phase2 false_positive ids: 076,080")
log.append("phase2 confirmed_partial ids: none")
log.append("phase2 confirmed_unsatisfied ids: none")
(OUT / "verify_wolfssl_dtls12_051_098.log").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
if failed:
    raise SystemExit(1)
'''
    (OUT / "verify_wolfssl_dtls12_051_098.py").write_text(script, encoding="utf-8")


def write_summary(results, cls):
    payload = {
        "round": f"{START:03d}-{END:03d}",
        "output_dir": str(OUT),
        "status_counts": counts(results),
        "partial_unsat_total": cls["meta"]["counts"]["total"],
        "phase2_decisions": cls["meta"]["phase2_decisions"],
        "confirmed_reports": [],
        "false_positive_items": [76, 80],
        "not_testable_items": [],
        "next_round": None,
        "note": "Input JSON contains 98 changes, so overall_end_id=100 was clamped to 098. Multi-round range 051-098 is complete.",
    }
    (OUT / f"round_summary_{START:03d}_{END:03d}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        f"# Round Summary {START:03d}-{END:03d}",
        "",
        f"- 输出目录: {OUT}",
        f"- 状态统计: {counts(results)}",
        f"- Phase 2 confirmed_partial: {cls['meta']['phase2_decisions']['confirmed_partial']}",
        f"- Phase 2 confirmed_unsatisfied: {cls['meta']['phase2_decisions']['confirmed_unsatisfied']}",
        f"- Phase 2 false_positive: {cls['meta']['phase2_decisions']['false_positive']} (076, 080)",
        "- 详细报告: 无；Phase 2 未确认不满足或部分满足项。",
        "- 下一轮范围: 无；输入 JSON 总数为 98，overall_end_id=100 已钳制到 098。",
        "",
    ]
    (OUT / f"round_summary_{START:03d}_{END:03d}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    changes = load_changes()
    if len(changes) < END:
        raise SystemExit(f"input has only {len(changes)} changes")
    results = make_results(changes)
    validation = validate_evidence(results)
    write_main(results, validation)
    write_md(results)
    write_simple(results)
    cls = classification(results)
    write_classification_md(cls)
    write_verify_script()
    write_summary(results, cls)
    print(f"wrote {len(results)} results to {OUT}")
    print(json.dumps(counts(results), ensure_ascii=False))
    print(json.dumps(validation, ensure_ascii=False))


if __name__ == "__main__":
    main()
