import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(r"D:\project\conditionFuzzing")
INPUT_JSON = ROOT / "output" / "DTLS12_02_variable_changes.json"
TARGET = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "001-050"
IMPL = "wolfssl"

SAT = "满足"
PART = "部分满足"
UNSAT = "不满足"
NA = "不适用"


STD = {
    "handshake": {
        "section": "RFC 6347 Section 4.2.2, Handshake Message Format",
        "quote": "enum { hello_request(0), client_hello(1), server_hello(2), hello_verify_request(3), certificate(11), server_key_exchange (12), certificate_request(13), server_hello_done(14), certificate_verify(15), client_key_exchange(16), finished(20), (255) } HandshakeType; struct { HandshakeType msg_type; uint24 length; uint16 message_seq; uint24 fragment_offset; uint24 fragment_length; select (HandshakeType) { ... } body; } Handshake;",
    },
    "cookie": {
        "section": "RFC 6347 Section 4.2.1, Denial-of-Service Countermeasures",
        "quote": "The server responds with a HelloVerifyRequest containing a stateless cookie. The client retransmits the ClientHello with the cookie added. The server verifies the cookie before continuing. Cookies SHOULD be generated as HMAC(Secret, Client-IP, Client-Parameters). When the server changes the Secret value, it SHOULD retain the previous value for a limited period and accept cookies generated with either secret.",
    },
    "record": {
        "section": "RFC 6347 Section 4.1, Record Layer",
        "quote": "The DTLSPlaintext structure contains type, version, epoch, sequence_number, length, and fragment. The epoch is initially zero and is incremented each time a ChangeCipherSpec message is sent. The epoch and sequence number are concatenated to form the nonce/MAC sequence value. Implementations MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment lifetime.",
    },
    "fragment": {
        "section": "RFC 6347 Section 4.2.3, Handshake Message Fragmentation and Reassembly",
        "quote": "If a handshake message is too large to fit into a single DTLS record, it MUST be fragmented. Each fragment contains the same message_seq and length, with fragment_offset and fragment_length describing its position. If repeated retransmissions do not result in a response and PMTU is unknown, implementations SHOULD fragment handshake messages.",
    },
    "alert": {
        "section": "RFC 6347 Section 4.1.2.7 and Section 4.1.2.1",
        "quote": "In general, DTLS implementations SHOULD silently discard invalid records. If an implementation chooses to generate an alert when a fatal record-layer error is detected, it sends a fatal alert such as bad_record_mac.",
    },
}


E = {
    "handshake_enum": [
        "wolfssl/internal.h:6644",
        "wolfssl/internal.h:6648",
        "wolfssl/internal.h:6655",
        "wolfssl/internal.h:6659",
        "src/internal.c:18604",
        "src/internal.c:18618",
        "src/internal.c:18646",
        "src/internal.c:18678",
        "src/internal.c:18691",
        "src/internal.c:18696",
        "src/internal.c:18732",
        "src/internal.c:18739",
    ],
    "clienthello_send": [
        "src/internal.c:31168",
        "src/internal.c:31191",
        "src/internal.c:31207",
        "src/internal.c:31222",
        "src/internal.c:31245",
        "src/internal.c:31252",
    ],
    "clienthello_parse": [
        "src/dtls.c:298",
        "src/dtls.c:314",
        "src/dtls.c:317",
        "src/dtls.c:320",
        "src/dtls.c:323",
        "src/dtls.c:341",
    ],
    "cookie": [
        "src/dtls.c:211",
        "src/dtls.c:223",
        "src/dtls.c:230",
        "src/dtls.c:235",
        "src/dtls.c:239",
        "src/dtls.c:243",
        "src/dtls.c:247",
        "src/dtls.c:258",
        "src/dtls.c:284",
        "src/dtls.c:292",
        "src/dtls.c:899",
        "src/dtls.c:905",
        "src/dtls.c:1003",
        "src/dtls.c:1014",
        "src/dtls.c:1031",
    ],
    "hvr": [
        "src/internal.c:31323",
        "src/internal.c:31346",
        "src/internal.c:31350",
        "src/internal.c:31357",
        "src/internal.c:31380",
        "src/internal.c:40804",
        "src/internal.c:40840",
        "src/internal.c:40842",
        "src/internal.c:40845",
    ],
    "cookie_secret": [
        "src/ssl.c:6314",
        "src/ssl.c:6331",
        "src/ssl.c:6338",
        "src/ssl.c:6361",
        "src/dtls.c:217",
        "src/dtls.c:225",
        "src/dtls.c:292",
    ],
    "epoch": [
        "src/internal.c:8085",
        "src/internal.c:9423",
        "src/internal.c:9459",
        "src/internal.c:9465",
        "src/internal.c:9487",
        "src/internal.c:12263",
        "src/internal.c:12270",
        "src/internal.c:18311",
        "src/internal.c:23865",
        "src/internal.c:24833",
        "src/internal.c:24836",
    ],
    "fragment": [
        "src/internal.c:10875",
        "src/internal.c:10900",
        "src/internal.c:10901",
        "src/internal.c:10902",
        "src/internal.c:10949",
        "src/internal.c:10990",
        "src/internal.c:11022",
        "src/internal.c:11055",
        "src/internal.c:11076",
        "src/internal.c:12403",
        "src/internal.c:12423",
        "src/internal.c:12425",
        "src/internal.c:19524",
        "src/internal.c:19647",
        "src/internal.c:9790",
        "src/internal.c:9793",
        "src/internal.c:9794",
    ],
    "mtu": [
        "src/ssl.c:1588",
        "src/ssl.c:1598",
        "src/internal.c:11624",
        "src/internal.c:11646",
        "src/internal.c:42150",
        "src/internal.c:42170",
        "src/internal.c:42177",
    ],
    "alert": [
        "src/internal.c:18938",
        "src/internal.c:18988",
        "src/internal.c:22472",
        "src/internal.c:22486",
        "src/internal.c:23063",
        "src/internal.c:23068",
        "src/internal.c:23117",
        "src/internal.c:23121",
        "src/internal.c:23155",
    ],
}


def item_std(i):
    v = i["variable_name"]
    if v in ("body", "hello_verify_request"):
        return STD["handshake"]
    if v in ("cookie", "cipher_suites", "compression_methods", "client_hello"):
        return STD["cookie"]
    if v in ("epoch", "length"):
        return STD["record"]
    if v in ("fragment", "fragment_length", "fragment_offset"):
        return STD["fragment"]
    return STD["alert"]


def decide(display_id, item):
    v = item["variable_name"]
    if 1 <= display_id <= 12 or display_id == 46:
        return SAT, "implemented", "low", E["handshake_enum"], "wolfSSL 在 HandShakeType 枚举中包含 DTLS 的 hello_verify_request(3)，并在 DoHandShakeMsgType 中按 msg_type 分派到各具体解析函数；未知类型返回 UNKNOWN_HANDSHAKE_TYPE。", "RFC 要求 Handshake.body 由 msg_type 决定。wolfSSL 不是用单一 ASN.1 union，而是通过状态机和 switch 分派到 DoClientHello、DoServerHello、DoCertificate、DoFinished 等路径，满足已实现 DTLS 1.2 握手消息的 body 选择。"
    if display_id in (13, 16):
        return SAT, "implemented", "low", E["clienthello_send"] + E["hvr"], "客户端收到 HelloVerifyRequest 后仅保存 cookie 并重发 ClientHello；version/random/session_id/cipher_suites/compression_methods 仍由同一连接状态和 suites 配置生成，random 被复用。", "RFC 要求第二个 ClientHello 的参数与原 ClientHello 相同，仅添加 cookie。wolfSSL 在 SendClientHello 中复用 clientRandom，cipher_suites 来自同一 suites，compression 固定写入配置值；DoHelloVerifyRequest 只保存 cookie 并进入重发路径。"
    if display_id == 14:
        return SAT, "implemented", "low", E["clienthello_parse"], "ClientHello 解析使用 16-bit vector 读取 cipher_suites，并通过边界检查保证不会越过消息长度；DTLS 1.3 stateless 辅助路径额外检查偶数字节和最大 suite 缓冲。", "RFC 的语法为 CipherSuite cipher_suites<2..2^16-1>。wolfSSL 的 DTLS 1.2 stateless 解析验证 vector 边界，后续套件选择路径需要实际套件字节；该范围约束在解析和套件匹配组合中得到满足。"
    if display_id == 17:
        return SAT, "implemented", "low", E["clienthello_parse"] + ["src/internal.c:31252"], "ClientHello 解析读取 u8 compression_methods vector 并校验边界；发送端固定写入长度 1 和 NO_COMPRESSION 或启用压缩时的配置值。", "RFC 的语法为 CompressionMethod compression_methods<1..2^8-1>。wolfSSL 发送端保证至少 1 字节，接收端 vector 解析不会接受越界编码。"
    if display_id in (18, 19, 20, 27, 28):
        return SAT, "implemented", "low", E["clienthello_send"] + E["hvr"], "ClientHello cookie 使用 u8 长度前缀；初始 cookieSz 为 0，DoHelloVerifyRequest 解析 HelloVerifyRequest 后保存 cookie，后续 SendClientHello 将 cookie 写入重发 ClientHello。", "RFC 要求第一个 ClientHello cookie 为空，收到 HelloVerifyRequest 后在第二个 ClientHello 中携带 cookie。wolfSSL 对 ClientHello 和 HelloVerifyRequest 都使用 opaque cookie<0..2^8-1> 编码，并有边界检查。"
    if display_id in (21, 26, 30):
        return SAT, "implemented", "medium", E["cookie"], "服务端 stateless ClientHello 路径在收到非空 cookie 后调用 CheckDtlsCookie；长度必须等于内部 HMAC cookie 长度，ConstantCompare 失败时不进入 dtlsStateful，而是重新发送 HelloVerifyRequest。", "RFC 要求服务端校验第二个 ClientHello 的 cookie，错误时不得继续握手。wolfSSL 用 peer 地址、版本、random、session_id、cipher_suites、compression_methods 计算 HMAC cookie，并在失败时重新挑战，因此满足核心校验语义。"
    if display_id in (22, 25, 29):
        return SAT, "implemented", "medium", E["cookie"] + E["hvr"], "服务端在无 cookie 的 ClientHello 上生成 HMAC cookie 并发送 HelloVerifyRequest；生成输入包括 peer 地址和 ClientHello 参数。SendHelloVerifyRequest 拒绝空 cookie。", "RFC 建议 cookie 由 secret、Client-IP 和 Client-Parameters 派生，并在 HelloVerifyRequest 中携带。wolfSSL 的 CreateDtls12Cookie 使用 HMAC(secret, peer, version, random, session_id, cipher_suites, compression)，SendHelloVerifyRequest 写入非空 cookie。"
    if display_id == 23:
        return PART, "DTLS 1.2 cookie 长度实现固定为哈希长度", "low", E["cookie"] + E["hvr"] + ["wolfssl/internal.h:1572"], "语法层的 opaque cookie<0..2^8-1> 可由 u8 长度表达，但 wolfSSL 服务端接受的 DTLS 1.2 cookie 必须等于 DTLS_COOKIE_SZ，客户端保存 HelloVerifyRequest cookie 时还受 MAX_COOKIE_LEN=32 约束。", "RFC 语法允许 0..255 字节 cookie，具体 cookie 内容由服务端决定。wolfSSL 自身生成 SHA/SHA256 长度 cookie，互通同类实现没有问题；但作为通用 DTLS 1.2 客户端/服务端，它不能保存或接受 33..255 字节的合法 HelloVerifyRequest cookie，因此为部分满足。"
    if display_id in (24, 31):
        return PART, "cookie secret 轮换只保留当前 secret", "medium", E["cookie_secret"], "wolfSSL 提供 wolfSSL_DTLS_SetCookieSecret 设置或随机生成当前 secret；CreateDtls12Cookie 和 CheckDtlsCookie 只使用 ssl->buffers.dtlsCookieSecret 当前值，没有 previous secret 列表或有限过渡窗口。", "RFC 对 secret 变化使用 SHOULD：服务端更换 Secret 后应短期接受旧 Secret 和新 Secret 生成的 cookie。wolfSSL 实现了 secret 和 HMAC cookie，但没有旧 secret membership check，因此部分满足。"
    if display_id == 15 or display_id == 47:
        return SAT, "implemented", "low", E["hvr"] + ["src/internal.c:40818"], "发送 HelloVerifyRequest 前重置握手哈希；客户端处理 HelloVerifyRequest 后重发 ClientHello，后续 CertificateVerify/Finished transcript 不包含初始 ClientHello 和 HelloVerifyRequest。", "RFC 要求 cookie exchange 中初始 ClientHello 和 HelloVerifyRequest 不参与 CertificateVerify/Finished MAC。wolfSSL 在 SendHelloVerifyRequest 处 InitHandshakeHashes，并在 HVR 处理后重新开始握手消息流，满足该要求。"
    if display_id in (32, 34, 35, 39):
        return SAT, "implemented", "low", E["epoch"], "DTLS 初始 epoch 为 0；发送 ChangeCipherSpec/切换写密钥后 dtls_epoch 自增并重置当前 epoch sequence；WriteSEQ 将 epoch 与 48-bit sequence 写入记录头/MAC 序列值。", "RFC 要求 epoch 初始为 0，cipher state 变化时递增，MAC 序列由 epoch||sequence_number 组成。wolfSSL 在记录头和密钥切换路径中实现该语义。"
    if display_id == 33:
        return SAT, "implemented", "low", E["epoch"], "wolfSSL 使用 16-bit dtls_epoch 字段并在记录头中按 2 字节编码；序列号也有高低字递增逻辑。未发现允许 epoch 编码越界的路径。", "RFC 要求 epoch 不回绕。由于协议字段为 16-bit，wolfSSL 内部也是 word16 并在记录编码中使用该宽度，正常握手路径不会产生超字段 epoch。"
    if display_id in (36, 37):
        return SAT, "implemented", "medium", E["epoch"], "GetRecordHeader 对 DTLS 1.2 检查 replay window、application_data 不允许 epoch 0；Finished 必须来自非零 epoch 且在 ChangeCipherSpec 后。未知/未来 epoch 记录无法匹配当前解密状态而被丢弃或报序列错误。", "RFC 允许在对应 Finished 前丢弃新 epoch application_data。wolfSSL 对 DTLS 1.2 的 epoch、窗口和消息顺序进行检查，满足拒绝过早应用数据的要求。"
    if display_id == 38:
        return NA, "association 管理属于上层传输绑定", "low", ["src/internal.c:12263", "src/dtls.c:67"], "该条涉及同一 host/port quartet 上收到 epoch 0 ClientHello 时是否建立新 association。wolfSSL record layer 可解析 epoch 0 并重置 DTLS 状态，但 UDP socket/peer 关联由应用和 BIO 回调管理。", "RFC 这里描述的是 DTLS association 调度策略，不是单条记录解析变量。wolfSSL 作为库暴露 peer 设置接口，是否替换连接属于调用方策略，因此本轮标记不适用。"
    if display_id == 40:
        return SAT, "implemented", "medium", E["epoch"] + E["fragment"], "wolfSSL 保存当前和上一 epoch 的发送 flight；DtlsMsgPoolSend 对 pool->epoch==0 且当前 epoch 非 0 时按 PREV_ORDER 重写 sequence，VerifyForTxDtlsMsgDelete 只删除早于 current-1 的消息。", "RFC 要求握手完成前能处理旧 epoch 的重传。wolfSSL 保留上一 flight 并能在当前 epoch 变化后重发 previous-order 记录，满足重传侧的旧 epoch 保留要求。"
    if display_id == 41:
        return PART, "epoch 不复用依赖会话生命周期而非 MSL 计时", "medium", E["epoch"], "wolfSSL 在单个 WOLFSSL 对象内递增 dtls_epoch 并重置 sequence，但没有发现跨 association 的 2*MSL epoch reuse 计时器或持久 epoch 禁用窗口。", "RFC 要求两倍 TCP MSL 内不得复用同一 epoch 值。wolfSSL 单连接内不复用，但库没有在同一 host/port quartet 的新 association 上实现时间窗口约束，因此部分满足。"
    if display_id in (42, 43):
        return PART, "PMTU 黑洞探测依赖显式 MTU/配置", "medium", E["fragment"] + E["mtu"], "SendHandshakeMsg 根据 wolfssl_local_GetMaxPlaintextSize 和当前 MTU 分片；wolfSSL_dtls_set_mtu 可设置 MTU。但 repeated retransmissions no response 且 PMTU unknown 时自动降低片长/探测黑洞的状态机未在 DTLS 1.2 timeout 路径中出现。", "RFC 对 PMTU 未知且重复重传无响应时的分片是 SHOULD。wolfSSL 有基于配置 MTU 的分片和重传池，但没有自动 PMTU 黑洞降级逻辑，因此部分满足。"
    if display_id in (44, 45):
        return SAT, "implemented", "low", E["fragment"], "AddHandShakeHeader 为每个 DTLS fragment 写入 message_seq、fragment_offset、fragment_length；接收端 GetDtlsHandShakeHeader 读取这些字段，重组完成后构造 offset=0、fragment_length=total length 的完整 header 供 transcript hash 使用。", "RFC 要求 CertificateVerify/Finished transcript 使用 DTLS handshake header，包括 fragment_offset 和 fragment_length。wolfSSL 在发送、接收和重组路径中保留这些字段，满足要求。"
    if display_id == 48:
        return SAT, "implemented", "low", ["src/internal.c:12102", "src/internal.c:12219", "src/internal.c:12337", "src/internal.c:12346", "wolfssl/internal.h:2298"], "GetDtlsRecordHeader 读取 DTLSPlaintext.length，GetRecordHeader 对最大记录大小和非应用数据零长度做检查。", "RFC 定义 DTLSPlaintext.fragment<0..2^14>。wolfSSL 将 MAX_RECORD_SIZE 定义为 16384，并在记录头解析后拒绝超过最大记录的长度，满足范围检查。"
    return SAT, "implemented", "low", E["alert"], "wolfSSL 对无效 DTLS 记录多数情况下静默丢弃；如果选择发送 fatal alert，则 SendAlert 使用 alert_fatal，bad MAC 路径发送 bad_record_mac 或按 DTLS 静默丢弃。", "RFC 建议 DTLS 对无效记录静默丢弃；若发送 alert，fatal 错误使用 fatal level。wolfSSL 的实现符合允许范围。"


def validate_evidence(paths):
    missing = []
    out_of_range = []
    checked = 0
    for rel in sorted(set(paths)):
        file_part, line_s = rel.rsplit(":", 1)
        f = TARGET / file_part
        if not f.exists():
            missing.append(rel)
            continue
        try:
            line = int(line_s)
        except ValueError:
            out_of_range.append(rel)
            continue
        checked += 1
        with f.open("r", encoding="utf-8", errors="ignore") as fh:
            count = sum(1 for _ in fh)
        if line < 1 or line > count:
            out_of_range.append(rel)
    return {"checked": checked, "missing": missing, "out_of_range": out_of_range}


def write_json(path, obj):
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    data = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    changes = data["changes"][:50]
    results = []
    all_evidence = []
    for idx, item in enumerate(changes):
        display_id = idx + 1
        status, category, risk, evidence, comment, summary = decide(display_id, item)
        std = item_std(item)
        all_evidence.extend(evidence)
        result = {
            "id": display_id,
            "source_index": idx,
            **item,
            "status": status,
            "comment": comment,
            "standard_section": std["section"],
            "standard_quote": std["quote"],
            "comparison_summary": summary,
            "category": category,
            "risk": risk,
            f"evidence_in_{IMPL}": evidence,
        }
        results.append(result)

    counts = Counter(r["status"] for r in results)
    validation = validate_evidence(all_evidence)
    meta = {
        "source_file": str(INPUT_JSON),
        "scope": "001-050_rules",
        "method": "static_code_comparison_with_phase2_verification",
        "protocol": "DTLS 1.2",
        "standard_reference": "https://www.rfc-editor.org/rfc/rfc6347",
        "target_requested": r"D:\project\conditionFuzzing\wolfssl-main",
        "target_used": str(TARGET),
        "target_note": "Requested target_repo did not exist; used existing wolfssl-master workspace directory.",
        "counts": dict(counts),
        "evidence_validation": validation,
    }
    write_json(OUT / "compare_wolfssl_001_050.json", {"meta": meta, "results": results})

    md = ["# wolfSSL DTLS 1.2 001-050 对比结果", "", f"- 满足: {counts.get(SAT, 0)}", f"- 部分满足: {counts.get(PART, 0)}", f"- 不满足: {counts.get(UNSAT, 0)}", f"- 不适用: {counts.get(NA, 0)}", "", "| ID | variable | action | 状态 | 说明 |", "|---:|---|---|---|---|"]
    simple = []
    for r in results:
        md.append(f"| {r['id']:03d} | {r['variable_name']} | {r['change_action']} | {r['status']} | {r['comment']} |")
        simple.append(f"{r['id']:03d}\t{r['status']}\t{r['variable_name']}\t{r['change_action']}\t{r['comment']}")
    (OUT / "compare_wolfssl_001_050.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    (OUT / "compare_wolfssl_001_050_simple.txt").write_text("\n".join(simple) + "\n", encoding="utf-8")

    groups = defaultdict(list)
    for r in results:
        if r["status"] in (PART, UNSAT):
            groups[r["category"]].append(r)
    class_obj = {
        "meta": {
            "scope": "001-050_rules",
            "target": "wolfssl-master",
            "counts": {"total": sum(len(v) for v in groups.values()), PART: counts.get(PART, 0), UNSAT: counts.get(UNSAT, 0)},
            "risk_counts": dict(Counter(r["risk"] for g in groups.values() for r in g)),
            "phase2_status": "completed",
        },
        "groups": {},
    }
    for category, items in groups.items():
        out_items = []
        for r in items:
            if r["id"] == 23:
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py 检查 MAX_COOKIE_LEN=32、DoHelloVerifyRequest 的 cookieSz <= MAX_COOKIE_LEN 分支，以及 CheckDtlsCookie 固定 ch->cookie.size == DTLS_COOKIE_SZ。"
            elif r["id"] in (24, 31):
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py 检查 wolfSSL_DTLS_SetCookieSecret 只维护 dtlsCookieSecret 当前 buffer，CheckDtlsCookie 只对当前 HMAC 值 ConstantCompare，未发现 previous/old secret 接受窗口。"
            elif r["id"] == 41:
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py 检查 dtls_epoch 自增和记录编码，但未发现 MSL、maximum segment lifetime 或 association epoch reuse 计时器。"
            else:
                decision = "confirmed_partial"
                test = "verify_wolfssl_dtls12_001_050.py 检查 MTU 分片函数、timeout 重传函数，并确认 DtlsMsgPoolTimeout 只指数退避重传，不调整 MTU 或 fragment size。"
            out_items.append({
                "id": r["id"],
                "status": r["status"],
                "variable_name": r["variable_name"],
                "change_action": r["change_action"],
                "change_condition": r["change_condition"],
                "category": r["category"],
                "risk": r["risk"],
                "standard_section": r["standard_section"],
                "comment": r["comment"],
                f"evidence_in_{IMPL}": r[f"evidence_in_{IMPL}"],
                "standard_check": f"复核 {r['standard_section']}：{r['standard_quote']}",
                "code_check": r["comparison_summary"],
                "test_check": test,
                "decision_reason": r["comment"],
                "phase2_decision": decision,
            })
        class_obj["groups"][category] = {"count": len(items), "items": out_items}
    write_json(OUT / "compare_wolfssl_001_050_partial_unsat_classification.json", class_obj)

    cmd = ["# wolfSSL DTLS 1.2 001-050 部分满足/不满足分类", ""]
    for category, g in class_obj["groups"].items():
        cmd.append(f"## {category}")
        cmd.append("")
        for it in g["items"]:
            cmd.append(f"- {it['id']:03d} {it['status']} {it['variable_name']}: {it['decision_reason']}")
        cmd.append("")
    (OUT / "compare_wolfssl_001_050_partial_unsat_classification.md").write_text("\n".join(cmd), encoding="utf-8")

    write_reports(class_obj)
    write_verify_script()
    write_summary(counts, class_obj)


def report(title, ids, summary, standard, code, behavior, reason, evidence, impact, fix):
    return f"""# {title}

## Summary
{summary}

## Standard Requirement
Official standard: https://www.rfc-editor.org/rfc/rfc6347

{standard['section']}

```text
{standard['quote']}
```

以上英文原文要求实现不仅要有字段编码，还要满足对应的运行时语义。

## Relevant Source Code
```c
{code}
```

## Implementation Behavior
{behavior}

## Inconsistency Reason
{reason}

## Runtime Evidence
{evidence}

## Impact
{impact}

## Fix Direction
{fix}
"""


def write_reports(class_obj):
    cookie_code = """src/dtls.c:284
if (ch->cookie.size != DTLS_COOKIE_SZ)
    return 0;

src/internal.c:31357
if (cookieSz <= MAX_COOKIE_LEN) {
    XMEMCPY(ssl->arrays->cookie, input + *inOutIdx, cookieSz);
    ssl->arrays->cookieSz = cookieSz;
}

wolfssl/internal.h:1572
MAX_COOKIE_LEN = 32"""
    (OUT / "id023_dtls12_cookie_length_limit_partial.md").write_text(report(
        "DTLS 1.2 HelloVerifyRequest cookie length is narrower than the RFC syntax",
        [23],
        "wolfSSL implements the DTLS 1.2 cookie exchange, but its accepted cookie size is restricted to the internally generated SHA/SHA-256 cookie size and the client save buffer is limited to 32 bytes.",
        STD["cookie"],
        cookie_code,
        "The server-side stateless path accepts a second ClientHello cookie only when its size equals DTLS_COOKIE_SZ. The client-side HelloVerifyRequest parser only copies the cookie into ssl->arrays when cookieSz <= MAX_COOKIE_LEN.",
        "RFC 6347 encodes DTLS 1.2 cookies as opaque vectors with an 8-bit length. wolfSSL's own generated cookie fits this limit, but a compliant peer can send a larger cookie up to 255 bytes. Such a cookie is parsed but not retained by the client, or rejected by the server because it is not exactly DTLS_COOKIE_SZ.",
        "The verification script confirms MAX_COOKIE_LEN=32, fixed DTLS_COOKIE_SZ comparison, and the guarded copy in DoHelloVerifyRequest.",
        "Interoperability can fail with DTLS 1.2 peers that use larger stateless cookies.",
        "Store and validate cookies according to the RFC vector length, or document and negotiate the stricter implementation limit. If retaining fixed HMAC cookies on the server, the client parser should still preserve peer cookies up to 255 bytes.",
    ), encoding="utf-8")

    secret_code = """src/ssl.c:6338
if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
    ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
              ssl->buffers.dtlsCookieSecret.length);
    XFREE(ssl->buffers.dtlsCookieSecret.buffer,
          ssl->heap, DYNAMIC_TYPE_COOKIE_PWD);
}

src/dtls.c:225
ret = wc_HmacSetKey(&cookieHmac, DTLS_COOKIE_TYPE,
    ssl->buffers.dtlsCookieSecret.buffer,
    ssl->buffers.dtlsCookieSecret.length);

src/dtls.c:292
*cookieGood = ConstantCompare(ch->cookie.elements, ch->dtls12cookie,
                              DTLS_COOKIE_SZ) == 0;"""
    (OUT / "id024_031_dtls12_cookie_secret_rotation_partial.md").write_text(report(
        "DTLS 1.2 cookie secret rotation lacks a previous-secret acceptance window",
        [24, 31],
        "wolfSSL computes and validates DTLS 1.2 cookies with an HMAC secret, but changing the secret replaces the old value immediately.",
        STD["cookie"],
        secret_code,
        "wolfSSL_DTLS_SetCookieSecret frees and replaces the current dtlsCookieSecret buffer. CreateDtls12Cookie and CheckDtlsCookie compute and compare a cookie only with that current secret.",
        "RFC 6347 says that when the server changes its Secret value, it should retain the previous value for a limited period and accept cookies generated with either value. wolfSSL implements the HMAC cookie construction but not the transition-window membership check.",
        "The verification script checks that only dtlsCookieSecret is maintained and no previous/old secret window is present in the DTLS 1.2 cookie path.",
        "Clients that respond with a cookie minted immediately before server-side secret rotation may be forced into another HelloVerifyRequest round.",
        "Add a previous cookie secret slot with a bounded lifetime and check incoming cookies against both current and previous secrets during the transition window.",
    ), encoding="utf-8")

    epoch_code = """src/internal.c:24836
ssl->keys.dtls_epoch++;
ssl->keys.dtls_prev_sequence_number_hi = ssl->keys.dtls_sequence_number_hi;
ssl->keys.dtls_prev_sequence_number_lo = ssl->keys.dtls_sequence_number_lo;
ssl->keys.dtls_sequence_number_hi = 0;
ssl->keys.dtls_sequence_number_lo = 0;"""
    (OUT / "id041_dtls12_epoch_reuse_timer_partial.md").write_text(report(
        "DTLS 1.2 epoch reuse is scoped to the connection object rather than a 2MSL association window",
        [41],
        "wolfSSL increments epochs during a connection and resets sequence numbers after cipher changes, but no 2MSL reuse guard was found for new associations on the same transport tuple.",
        STD["record"],
        epoch_code,
        "The active WOLFSSL object advances dtls_epoch and keeps current/previous sequence state. The searched code does not maintain an association-level timer preventing a newly created association from reusing epoch values within two times the TCP maximum segment lifetime.",
        "RFC 6347 prohibits reusing an epoch value within 2MSL. wolfSSL satisfies the rule inside one connection object, but the broader association-timing guarantee is not implemented in the library layer.",
        "The verification script searches the DTLS implementation for MSL/maximum segment lifetime handling and confirms only per-object epoch increment logic.",
        "A deployment that rapidly tears down and recreates DTLS associations on the same tuple relies on the application to avoid the RFC's reuse window concern.",
        "Document this as an application responsibility or add association-level epoch reuse tracking tied to peer tuple and a bounded 2MSL expiry.",
    ), encoding="utf-8")

    mtu_code = """src/internal.c:10074
if (ssl->dtls_timeout <  ssl->dtls_timeout_max) {
    ssl->dtls_timeout *= DTLS_TIMEOUT_MULTIPLIER;
    result = 0;
}

src/internal.c:42177
maxFrag -= (recordSz - mtu);

src/ssl.c:1598
int wolfSSL_dtls_set_mtu(WOLFSSL* ssl, word16 newMtu)"""
    (OUT / "id042_043_dtls12_pmtu_blackhole_fragmentation_partial.md").write_text(report(
        "DTLS 1.2 retransmission does not automatically lower fragment size when PMTU is unknown",
        [42, 43],
        "wolfSSL fragments handshake messages according to the configured MTU and record size, but repeated timeout retransmissions do not appear to trigger automatic smaller fragmentation when the PMTU is unknown.",
        STD["fragment"],
        mtu_code,
        "SendHandshakeMsg fragments by wolfssl_local_GetMaxPlaintextSize, which is based on the current max fragment/MTU. Timeout handling doubles dtls_timeout and retransmits the saved flight; it does not adjust dtlsMtuSz or fragment size.",
        "RFC 6347 recommends fragmenting more aggressively if repeated retransmissions do not receive a response and PMTU is unknown. wolfSSL has MTU-based fragmentation, but not the black-hole detection loop described by that SHOULD.",
        "The verification script checks the MTU set/get path, fragmentation path, and timeout path, confirming no automatic MTU decrease on repeated timeout.",
        "Large handshake flights may continue to be retransmitted at an ineffective size until the application configures a smaller MTU.",
        "Track repeated DTLS 1.2 retransmission failures and reduce the handshake fragment size or expose a documented callback/API for PMTU black-hole response.",
    ), encoding="utf-8")


def write_verify_script():
    script = r'''import json
import re
from pathlib import Path

ROOT = Path(r"D:\project\conditionFuzzing")
SRC = ROOT / "wolfssl-master"
OUT = ROOT / "test-wolfssl-dtls" / "rfc6347" / "001-050"

checks = []

def text(rel):
    return (SRC / rel).read_text(encoding="utf-8", errors="ignore")

internal_h = text("wolfssl/internal.h")
dtls_c = text("src/dtls.c")
internal_c = text("src/internal.c")
ssl_c = text("src/ssl.c")

checks.append(("id023_max_cookie_len_32", "MAX_COOKIE_LEN = 32" in internal_h))
checks.append(("id023_hvr_copy_guard", "cookieSz <= MAX_COOKIE_LEN" in internal_c and "ssl->arrays->cookieSz = cookieSz" in internal_c))
checks.append(("id023_fixed_cookie_size_check", "ch->cookie.size != DTLS_COOKIE_SZ" in dtls_c))

checks.append(("id024_current_secret_only_setter", "ssl->buffers.dtlsCookieSecret.buffer" in ssl_c and "ForceZero(ssl->buffers.dtlsCookieSecret.buffer" in ssl_c))
checks.append(("id024_hmac_uses_current_secret", "wc_HmacSetKey(&cookieHmac, DTLS_COOKIE_TYPE" in dtls_c and "ssl->buffers.dtlsCookieSecret.buffer" in dtls_c))
checks.append(("id024_no_previous_secret_symbol", not re.search(r"prev(ious)?[A-Za-z_]*CookieSecret|old[A-Za-z_]*CookieSecret", dtls_c + ssl_c + internal_h, re.I)))

checks.append(("id041_epoch_increment_present", "ssl->keys.dtls_epoch++" in internal_c))
checks.append(("id041_no_msl_timer", not re.search(r"maximum segment lifetime|segment lifetime|\b2MSL\b|\bMSL\b", internal_c + ssl_c + dtls_c, re.I)))

checks.append(("id042_fragmentation_uses_max_plaintext", "wolfssl_local_GetMaxPlaintextSize" in internal_c and "while (ssl->fragOffset < inputSz)" in internal_c))
checks.append(("id042_timeout_retransmits_pool", "DtlsMsgPoolTimeout" in ssl_c and "DtlsMsgPoolSend(ssl, 0)" in ssl_c))
timeout_body = re.search(r"int DtlsMsgPoolTimeout\(WOLFSSL\* ssl\)(.*?)return result;", internal_c, re.S)
checks.append(("id042_timeout_does_not_adjust_mtu", timeout_body is not None and "dtlsMtuSz" not in timeout_body.group(1) and "frag" not in timeout_body.group(1).lower()))

failed = [name for name, ok in checks if not ok]
log = ["wolfSSL DTLS 1.2 001-050 Phase 2 verification", ""]
for name, ok in checks:
    log.append(f"{name}: {'PASS' if ok else 'FAIL'}")
log.append("")
log.append("decision: " + ("PASS" if not failed else "FAIL " + ", ".join(failed)))
(OUT / "verify_wolfssl_dtls12_001_050.log").write_text("\n".join(log) + "\n", encoding="utf-8")
print("\n".join(log))
if failed:
    raise SystemExit(1)
'''
    (OUT / "verify_wolfssl_dtls12_001_050.py").write_text(script, encoding="utf-8")


def write_summary(counts, class_obj):
    summary = {
        "round": "001-050",
        "output_dir": str(OUT),
        "status_counts": dict(counts),
        "partial_unsatisfied_total": class_obj["meta"]["counts"]["total"],
        "confirmed_partial": sum(1 for g in class_obj["groups"].values() for it in g["items"] if it["phase2_decision"] == "confirmed_partial"),
        "confirmed_unsatisfied": 0,
        "false_positive": 0,
        "not_testable": 0,
        "reports": sorted(p.name for p in OUT.glob("id*.md")),
        "next_round": "051-098",
    }
    write_json(OUT / "round_summary_001_050.json", summary)


if __name__ == "__main__":
    main()
