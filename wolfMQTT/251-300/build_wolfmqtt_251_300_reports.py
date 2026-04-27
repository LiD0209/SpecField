#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[2]
OUT_DIR = Path(__file__).resolve().parent

SOURCE_JSON = WORKSPACE / "output" / "02_variable_changes.json"

OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_251_300.json"
OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_251_300.md"
OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_251_300_simple.txt"
OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_251_300_partial_unsat_classification.json"
OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_251_300_partial_unsat_classification.md"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_counts(counter: Counter) -> dict:
    return {
        "满足": counter.get("满足", 0),
        "部分满足": counter.get("部分满足", 0),
        "不满足": counter.get("不满足", 0),
        "不适用": counter.get("不适用", 0),
        "待确认": counter.get("待确认", 0),
    }


def validate_evidence_refs(refs: list[str]) -> dict:
    missing_files: list[str] = []
    out_of_range: list[str] = []
    bad_format: list[str] = []
    cache: dict[Path, list[str]] = {}

    for ref in refs:
        m = re.match(r"^([^:]+):(\d+)$", ref)
        if not m:
            bad_format.append(ref)
            continue
        rel_path = m.group(1)
        line_no = int(m.group(2))
        abs_path = WORKSPACE / rel_path
        if not abs_path.exists():
            missing_files.append(ref)
            continue
        if abs_path not in cache:
            cache[abs_path] = abs_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        line_count = len(cache[abs_path])
        if line_no < 1 or line_no > line_count:
            out_of_range.append(ref)

    return {
        "total_references": len(refs),
        "missing_files": sorted(set(missing_files)),
        "out_of_range": sorted(set(out_of_range)),
        "bad_format": sorted(set(bad_format)),
        "all_locatable": not (missing_files or out_of_range or bad_format),
    }


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def rule_mapping() -> dict[int, dict]:
    return {
        251: {
            "status": "不满足",
            "comment": "未发现对 Topic Filter 中 U+0000 的显式拒绝；仅解码长度和边界，不校验禁用字符。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
                "wolfMQTT-master/src/mqtt_packet.c:1877",
                "wolfMQTT-master/src/mqtt_broker.c:1464",
            ],
            "category": "UTF-8 禁用字符校验缺失",
            "risk_level": "high",
            "reason": "Topic Filter 允许携带 NUL 会导致匹配和字符串处理出现语义偏差。",
        },
        252: {
            "status": "满足",
            "comment": "字符串采用 2 字节长度字段解码，编码侧也限制 >65535 字节，满足长度上限约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:285",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:366",
            ],
        },
        253: {
            "status": "满足",
            "comment": "订阅匹配时，非通配符层级按字符逐个比较实现。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2533",
                "wolfMQTT-master/src/mqtt_broker.c:2544",
                "wolfMQTT-master/src/mqtt_broker.c:2547",
            ],
        },
        254: {
            "status": "部分满足",
            "comment": "支持通过编译开关禁用通配符匹配，但禁用后并未在 SUBSCRIBE 入站阶段拒绝含通配符的 Topic Filter。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2572",
                "wolfMQTT-master/src/mqtt_broker.c:3066",
                "wolfMQTT-master/src/mqtt_broker.c:3087",
            ],
            "category": "禁用通配符场景下订阅拒绝缺失",
            "risk_level": "medium",
            "reason": "当配置为不支持通配符时，行为更接近“按普通字符存储”，而非协议要求的无效处理。",
        },
        255: {
            "status": "部分满足",
            "comment": "SUBSCRIBE 的 Topic Filter 走长度前缀字符串解码，但无 UTF-8 语义校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1877",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "仅做长度解码无法覆盖非法 UTF-8 序列场景。",
        },
        256: {
            "status": "部分满足",
            "comment": "UNSUBSCRIBE 的 Topic Filter 同样仅做长度解码，无 UTF-8 合法性判断。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2165",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "无法拦截非法 UTF-8 的 Topic Filter。",
        },
        257: {
            "status": "满足",
            "comment": "同一客户端对同一 Topic Filter 重复订阅时执行更新 QoS，而非创建重复订阅。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1470",
                "wolfMQTT-master/src/mqtt_broker.c:1476",
                "wolfMQTT-master/src/mqtt_broker.c:1490",
            ],
        },
        258: {
            "status": "满足",
            "comment": "实现了 $ 前缀 Topic Name 与前导通配符过滤器（#/+）不匹配的约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2528",
                "wolfMQTT-master/src/mqtt_broker.c:2529",
                "wolfMQTT-master/src/mqtt_broker.c:2530",
            ],
        },
        259: {
            "status": "满足",
            "comment": "匹配逻辑基于字符逐位比较与通配符规则分支，未做归一化或字符替换。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2533",
                "wolfMQTT-master/src/mqtt_broker.c:2544",
                "wolfMQTT-master/src/mqtt_broker.c:2569",
            ],
        },
        260: {
            "status": "部分满足",
            "comment": "匹配阶段仅当 # 为末尾字符才返回匹配；但未在订阅入站阶段显式判定非法位置。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2534",
                "wolfMQTT-master/src/mqtt_broker.c:2535",
                "wolfMQTT-master/src/mqtt_broker.c:3066",
            ],
            "category": "Topic Filter 语法约束校验不足",
            "risk_level": "medium",
            "reason": "非法过滤器未被拒绝，只是在匹配时可能不命中。",
        },
        261: {
            "status": "不满足",
            "comment": "未实现“+ 必须占据整级”的显式语法校验；匹配器会将 + 作为字符位置通配处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2537",
                "wolfMQTT-master/src/mqtt_broker.c:2541",
                "wolfMQTT-master/src/mqtt_broker.c:2543",
            ],
            "category": "Topic Filter 语法约束校验不足",
            "risk_level": "high",
            "reason": "可能接受规范外过滤器并产生非预期匹配结果。",
        },
        262: {
            "status": "不满足",
            "comment": "未发现 Topic Name 最小长度（>=1）的显式拒绝；空 Topic Name 可进入后续流程。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_broker.c:3214",
                "wolfMQTT-master/src/mqtt_broker.c:3227",
            ],
            "category": "Topic Name 基本合法性校验缺失",
            "risk_level": "high",
            "reason": "空主题名不符合条目要求，可能导致路由语义不确定。",
        },
        263: {
            "status": "不满足",
            "comment": "未对 Topic Name 的 U+0000 做拒绝校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_broker.c:3233",
            ],
            "category": "UTF-8 禁用字符校验缺失",
            "risk_level": "high",
            "reason": "NUL 字符会破坏 C 字符串语义并影响匹配一致性。",
        },
        264: {
            "status": "部分满足",
            "comment": "接收侧使用长度前缀解码字符串，但未进行 UTF-8 编码合法性检查。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "非法 UTF-8 字节序列无法被协议层识别。",
        },
        265: {
            "status": "部分满足",
            "comment": "Topic Name 解析流程仅完成长度与边界校验，未做 UTF-8 语义验证。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "不能满足“字符数据必须是有效 UTF-8”要求。",
        },
        266: {
            "status": "不满足",
            "comment": "Topic Name 未实现 U+0000 特判拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_broker.c:3239",
            ],
            "category": "UTF-8 禁用字符校验缺失",
            "risk_level": "high",
            "reason": "含 NUL 的主题名可能在不同路径被截断解释。",
        },
        267: {
            "status": "满足",
            "comment": "Topic Name 使用 2 字节长度字段（0..65535）并带边界检查。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:285",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
        },
        268: {
            "status": "满足",
            "comment": "编码侧限制 UTF-8 字符串长度不得超过 65535 字节。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:361",
                "wolfMQTT-master/src/mqtt_packet.c:366",
                "wolfMQTT-master/src/mqtt_packet.c:367",
            ],
        },
        269: {
            "status": "部分满足",
            "comment": "Broker 入站 PUBLISH 会拒绝 Topic Name 中的 +/#；但编码 API 未做同等限制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3213",
                "wolfMQTT-master/src/mqtt_broker.c:3217",
                "wolfMQTT-master/src/mqtt_packet.c:1307",
            ],
            "category": "Topic Name 通配符约束仅在 Broker 入站侧覆盖",
            "risk_level": "medium",
            "reason": "发送侧仍可构造不合规 Topic Name。",
        },
        270: {
            "status": "部分满足",
            "comment": "与 ID269 一致：仅 Broker 接收路径显式拒绝通配符 Topic Name。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3213",
                "wolfMQTT-master/src/mqtt_broker.c:3217",
                "wolfMQTT-master/src/mqtt_packet.c:1361",
            ],
            "category": "Topic Name 通配符约束仅在 Broker 入站侧覆盖",
            "risk_level": "medium",
            "reason": "全链路一致性不足。",
        },
        271: {
            "status": "不满足",
            "comment": "未实现“所有 Topic Name 至少 1 字符”的统一校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1307",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_broker.c:3227",
            ],
            "category": "Topic Name 基本合法性校验缺失",
            "risk_level": "high",
            "reason": "空主题名可能被接收/编码。",
        },
        272: {
            "status": "不满足",
            "comment": "未发现 Topic Name 的 NUL 字符全局拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_broker.c:3233",
            ],
            "category": "UTF-8 禁用字符校验缺失",
            "risk_level": "high",
            "reason": "字符串截断和路由一致性风险持续存在。",
        },
        273: {
            "status": "满足",
            "comment": "Topic Name 长度上限通过编码限制和 2 字节长度字段机制得到保证。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:366",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
        },
        274: {
            "status": "满足",
            "comment": "订阅匹配中，非通配符层级按字符精确相等进行比较。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2533",
                "wolfMQTT-master/src/mqtt_broker.c:2544",
                "wolfMQTT-master/src/mqtt_broker.c:2569",
            ],
        },
        275: {
            "status": "满足",
            "comment": "Broker 向订阅者转发前通过 BrokerTopicMatch 判定 Topic Name 与 Topic Filter 是否匹配。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3293",
                "wolfMQTT-master/src/mqtt_broker.c:3294",
                "wolfMQTT-master/src/mqtt_broker.c:3315",
            ],
        },
        276: {
            "status": "部分满足",
            "comment": "PUBLISH 的 Topic Name 以长度前缀字符串编解码，但无 UTF-8 语义校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1361",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_packet.c:338",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "无法识别非法 UTF-8 Topic Name。",
        },
        277: {
            "status": "部分满足",
            "comment": "接收侧 Broker 拒绝 Topic Name 中 +/#，但发送编码路径未统一校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3213",
                "wolfMQTT-master/src/mqtt_broker.c:3217",
                "wolfMQTT-master/src/mqtt_packet.c:1307",
            ],
            "category": "Topic Name 通配符约束仅在 Broker 入站侧覆盖",
            "risk_level": "medium",
            "reason": "发送端约束不足。",
        },
        278: {
            "status": "部分满足",
            "comment": "PUBLISH Topic Name 的 UTF-8 校验仍停留在长度层，缺少编码语义验证。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1434",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "对 malformed UTF-8 缺乏防护。",
        },
        279: {
            "status": "满足",
            "comment": "PUBLISH 可变头首字段按实现先编解码 Topic Name，再处理 Packet Identifier/属性。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1360",
                "wolfMQTT-master/src/mqtt_packet.c:1361",
                "wolfMQTT-master/src/mqtt_packet.c:1434",
            ],
        },
        280: {
            "status": "满足",
            "comment": "Topic Name 以 $ 开头时不会与前导 +/# 的 Topic Filter 匹配。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2528",
                "wolfMQTT-master/src/mqtt_broker.c:2529",
                "wolfMQTT-master/src/mqtt_broker.c:2530",
            ],
        },
        281: {
            "status": "满足",
            "comment": "匹配算法未做归一化或替换，按原始字符流进行判断。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2533",
                "wolfMQTT-master/src/mqtt_broker.c:2544",
                "wolfMQTT-master/src/mqtt_broker.c:2569",
            ],
        },
        282: {
            "status": "部分满足",
            "comment": "CONNECT 解码仅在 User Name Flag=1 时解析用户名；但未校验“Flag=0 时剩余载荷必须不含用户名字段”。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1142",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "CONNECT User Name Flag 与载荷一致性校验不足",
            "risk_level": "high",
            "reason": "可能接受 Flag/载荷不一致的 CONNECT 报文。",
        },
        283: {
            "status": "部分满足",
            "comment": "同 ID282：条件分支存在，但未做“多余用户名字段”一致性拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "CONNECT User Name Flag 与载荷一致性校验不足",
            "risk_level": "high",
            "reason": "协议一致性约束不完整。",
        },
        284: {
            "status": "满足",
            "comment": "当 User Name Flag=1 时，解码路径会读取用户名字段；字段缺失将触发边界错误返回。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1121",
                "wolfMQTT-master/src/mqtt_packet.c:1125",
            ],
        },
        285: {
            "status": "满足",
            "comment": "同 ID284：Flag=1 会触发用户名字段读取，满足存在性约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1119",
                "wolfMQTT-master/src/mqtt_packet.c:1127",
            ],
        },
        286: {
            "status": "部分满足",
            "comment": "实现中确实使用返回码 0x04（v3）表示用户名/密码问题，但覆盖了“认证失败”与“格式错误”两类语义。",
            "evidence": [
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:389",
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:390",
                "wolfMQTT-master/src/mqtt_broker.c:2959",
            ],
            "category": "CONNECT 用户名/密码错误码语义覆盖不精确",
            "risk_level": "medium",
            "reason": "错误码语义粒度与条目描述存在偏差。",
        },
        287: {
            "status": "部分满足",
            "comment": "User Name 字段接收侧仅做长度解码，无 UTF-8 合法性校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1119",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "无法严格满足 UTF-8 接收校验要求。",
        },
        288: {
            "status": "满足",
            "comment": "CONNECT 载荷解析顺序中，User Name Flag=1 时用户名字段作为后续字段被读取。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1127",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
            ],
        },
        289: {
            "status": "部分满足",
            "comment": "User Name 未做 UTF-8 语义级合法性判断，仅长度边界检查。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1119",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "无法拦截非法 UTF-8 用户名。",
        },
        290: {
            "status": "不满足",
            "comment": "未发现对 User Name 中 U+0000 的显式拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1119",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_broker.c:2860",
            ],
            "category": "UTF-8 禁用字符校验缺失",
            "risk_level": "high",
            "reason": "NUL 可能导致认证字符串比较语义偏移。",
        },
        291: {
            "status": "满足",
            "comment": "User Name 解析基于 2 字节长度字段并做边界检查，满足 0..65535 字节范围。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:285",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:1124",
            ],
        },
        292: {
            "status": "部分满足",
            "comment": "CONNECT 中 User Name 使用长度前缀字符串格式，但未校验 UTF-8 语义合法性。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1119",
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
            ],
            "category": "UTF-8 语义校验缺失（仅长度解码）",
            "risk_level": "high",
            "reason": "格式层满足但语义层不足。",
        },
        293: {
            "status": "部分满足",
            "comment": "发送侧编码已实现“Password 不能在 Username 为空时单独出现”；接收侧 CONNECT 解码未显式验证该约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:774",
                "wolfMQTT-master/src/mqtt_packet.c:776",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
            ],
            "category": "CONNECT User Name Flag 与载荷一致性校验不足",
            "risk_level": "high",
            "reason": "入站 CONNECT 可能放行 Flag 组合违规报文。",
        },
        294: {
            "status": "部分满足",
            "comment": "实现通过 Flag 位驱动字段解析，但未严格拒绝 Flag=0 时附带用户名数据的异常载荷。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1142",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "CONNECT User Name Flag 与载荷一致性校验不足",
            "risk_level": "high",
            "reason": "缺失最终“已消费长度==remaining length”的一致性检查。",
        },
        295: {
            "status": "满足",
            "comment": "编码侧当用户名存在时会设置 User Name Flag=1。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:882",
                "wolfMQTT-master/src/mqtt_packet.c:883",
                "wolfMQTT-master/src/mqtt_packet.c:937",
            ],
        },
        296: {
            "status": "满足",
            "comment": "当 User Name Flag=1 时，CONNECT 解析会读取用户名字段。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1119",
                "wolfMQTT-master/src/mqtt_packet.c:1127",
            ],
        },
        297: {
            "status": "部分满足",
            "comment": "DISCONNECT 编码在 MQTT3 场景为无可变头；但实现同时支持 MQTT5 可变头，且 broker 收包路径未显式校验 remaining length=0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2446",
                "wolfMQTT-master/src/mqtt_packet.c:2492",
                "wolfMQTT-master/src/mqtt_broker.c:3579",
            ],
            "category": "控制报文无可变头约束校验不足",
            "risk_level": "medium",
            "reason": "协议版本分支与收包校验粒度导致约束非强一致。",
        },
        298: {
            "status": "部分满足",
            "comment": "PINGREQ 发送侧固定 remaining length=0；broker 收到 PINGREQ 后直接回 PINGRESP，未显式拒绝附加可变头/载荷。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2355",
                "wolfMQTT-master/src/mqtt_packet.c:2365",
                "wolfMQTT-master/src/mqtt_broker.c:3576",
            ],
            "category": "控制报文无可变头约束校验不足",
            "risk_level": "medium",
            "reason": "接收侧缺少 strict format check。",
        },
        299: {
            "status": "部分满足",
            "comment": "PINGRESP 编码为无可变头；但 PINGRESP 解码未校验 remaining length 必须为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2591",
                "wolfMQTT-master/src/mqtt_broker.c:2592",
                "wolfMQTT-master/src/mqtt_packet.c:2389",
            ],
            "category": "控制报文无可变头约束校验不足",
            "risk_level": "medium",
            "reason": "接收侧可放行非零 remaining length 的 PINGRESP。",
        },
        300: {
            "status": "部分满足",
            "comment": "Will 处理逻辑在 Will Flag=1 时会存储并置位 has_will；但条目中的“Connect accepted => Will Flag=1”并非实现的普遍约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1000",
                "wolfMQTT-master/src/mqtt_broker.c:2789",
                "wolfMQTT-master/src/mqtt_broker.c:2845",
            ],
            "category": "Will Flag 条目语义与实现存在条件差异",
            "risk_level": "medium",
            "reason": "实现遵循“客户端声明 will 才置位”，与该条目字面条件存在差异。",
        },
    }


def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:
    results: list[dict] = []
    for i, change in enumerate(changes, start=251):
        m = mapping[i]
        results.append(
            {
                "id": i,
                "source_index": i - 1,
                "variable_name": change.get("variable_name", ""),
                "change_action": change.get("change_action", ""),
                "change_condition": change.get("change_condition", ""),
                "old_value": change.get("old_value", ""),
                "new_value": change.get("new_value", ""),
                "related_state_or_step": change.get("related_state_or_step", ""),
                "source_chunk_id": change.get("source_chunk_id", ""),
                "status": m["status"],
                "comment": m["comment"],
                "evidence_in_wolfmqtt": m.get("evidence", []),
            }
        )

    counts = normalize_counts(Counter([r["status"] for r in results]))
    all_refs: list[str] = []
    for r in results:
        all_refs.extend(r.get("evidence_in_wolfmqtt", []))
    evidence_check = validate_evidence_refs(all_refs)

    meta = {
        "source_file": str(SOURCE_JSON),
        "scope": "source_changes_index_250_to_299",
        "display_scope": "251-300",
        "method": "static_code_comparison",
        "target": "wolfMQTT-master",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "counts": counts,
        "evidence_validation": evidence_check,
    }
    return {"meta": meta, "results": results}


def build_compare_md(compare: dict) -> str:
    meta = compare["meta"]
    rows = compare["results"]
    lines = [
        "# wolfMQTT-master 251-300 对比结果",
        "",
        f"- 对比源：`output/02_variable_changes.json` 的 `250..299`（共 {len(rows)} 条）",
        "- 目标代码：`wolfMQTT-master`",
        f"- 满足：{meta['counts']['满足']}",
        f"- 部分满足：{meta['counts']['部分满足']}",
        f"- 不满足：{meta['counts']['不满足']}",
        f"- 不适用：{meta['counts']['不适用']}",
        f"- 待确认：{meta['counts']['待确认']}",
        (
            "- 证据定位校验："
            f"all_locatable={meta['evidence_validation']['all_locatable']}, "
            f"references={meta['evidence_validation']['total_references']}"
        ),
        "",
        "| ID | source_idx | variable | action | 状态 | 结论说明 | 证据数 |",
        "|---:|---:|---|---|---|---|---:|",
    ]
    for r in rows:
        lines.append(
            "| {id} | {idx} | {var} | {act} | {status} | {comment} | {ev_count} |".format(
                id=r["id"],
                idx=r["source_index"],
                var=md_escape(r["variable_name"]),
                act=md_escape(r["change_action"]),
                status=r["status"],
                comment=md_escape(r["comment"]),
                ev_count=len(r.get("evidence_in_wolfmqtt", [])),
            )
        )
    lines.append("")
    return "\n".join(lines)


def build_simple_txt(compare: dict) -> str:
    lines: list[str] = []
    for r in compare["results"]:
        lines.append(f"{r['id']:03d}\t{r['status']}\t{r['comment']}")
    return "\n".join(lines) + "\n"


def build_classification(compare: dict, mapping: dict[int, dict]) -> dict:
    rows = [r for r in compare["results"] if r["status"] in ("部分满足", "不满足")]
    out: list[dict] = []
    for r in rows:
        m = mapping[r["id"]]
        out.append(
            {
                "id": r["id"],
                "status": r["status"],
                "category": m.get("category", "未分类"),
                "risk_level": m.get("risk_level", "medium"),
                "reason": m.get("reason", r["comment"]),
                "variable_name": r["variable_name"],
                "change_action": r["change_action"],
                "change_condition": r["change_condition"],
                "source_index": r["source_index"],
                "source_chunk_id": r["source_chunk_id"],
                "original_comment": r["comment"],
                "evidence_in_wolfmqtt": r.get("evidence_in_wolfmqtt", []),
            }
        )

    status_counter = Counter([x["status"] for x in out])
    risk_counter = Counter([x["risk_level"] for x in out])
    category_summary: dict[str, dict] = defaultdict(
        lambda: {"count": 0, "partial": 0, "unsatisfied": 0}
    )

    for row in out:
        c = category_summary[row["category"]]
        c["count"] += 1
        if row["status"] == "部分满足":
            c["partial"] += 1
        else:
            c["unsatisfied"] += 1

    return {
        "scope": "wolfMQTT-master 251-300 partial+unsatisfied",
        "total_reviewed": len(out),
        "status_summary": {
            "部分满足": status_counter.get("部分满足", 0),
            "不满足": status_counter.get("不满足", 0),
        },
        "risk_summary": {
            "low": risk_counter.get("low", 0),
            "medium": risk_counter.get("medium", 0),
            "high": risk_counter.get("high", 0),
        },
        "category_summary": dict(sorted(category_summary.items(), key=lambda x: x[0])),
        "results": out,
    }


def build_classification_md(cls: dict) -> str:
    lines = [
        "# wolfMQTT-master 251-300 未满足/部分满足分类",
        "",
        f"- total_reviewed: {cls['total_reviewed']}",
        f"- 部分满足: {cls['status_summary']['部分满足']}",
        f"- 不满足: {cls['status_summary']['不满足']}",
        (
            "- 风险分布: "
            f"low={cls['risk_summary']['low']}, "
            f"medium={cls['risk_summary']['medium']}, "
            f"high={cls['risk_summary']['high']}"
        ),
        "",
        "## 分类汇总",
        "",
        "| 分类 | 数量 | 部分满足 | 不满足 |",
        "|---|---:|---:|---:|",
    ]
    for cat, s in cls["category_summary"].items():
        lines.append(f"| {md_escape(cat)} | {s['count']} | {s['partial']} | {s['unsatisfied']} |")

    lines.extend(
        [
            "",
            "## 明细",
            "",
            "| ID | source_idx | 状态 | 风险 | 分类 | 原因 |",
            "|---:|---:|---|---|---|---|",
        ]
    )
    for r in cls["results"]:
        lines.append(
            "| {id} | {idx} | {status} | {risk} | {cat} | {reason} |".format(
                id=r["id"],
                idx=r["source_index"],
                status=r["status"],
                risk=r["risk_level"],
                cat=md_escape(r["category"]),
                reason=md_escape(r["reason"]),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    source = load_json(SOURCE_JSON)
    changes = source.get("changes", [])[250:300]
    if len(changes) != 50:
        raise RuntimeError(f"Expected 50 items for 251-300, got {len(changes)}")

    mapping = rule_mapping()
    if sorted(mapping.keys()) != list(range(251, 301)):
        raise RuntimeError("Rule mapping must cover IDs 251..300")

    compare = build_compare(changes, mapping)
    save_json(OUT_COMPARE_JSON, compare)
    OUT_COMPARE_MD.write_text(build_compare_md(compare), encoding="utf-8")
    OUT_SIMPLE_TXT.write_text(build_simple_txt(compare), encoding="utf-8")

    cls = build_classification(compare, mapping)
    save_json(OUT_CLASS_JSON, cls)
    OUT_CLASS_MD.write_text(build_classification_md(cls), encoding="utf-8")

    print("Generated:")
    print(f"- {OUT_COMPARE_JSON}")
    print(f"- {OUT_COMPARE_MD}")
    print(f"- {OUT_SIMPLE_TXT}")
    print(f"- {OUT_CLASS_JSON}")
    print(f"- {OUT_CLASS_MD}")


if __name__ == "__main__":
    main()

