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

OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_101_150.json"
OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_101_150.md"
OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_101_150_simple.txt"
OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_101_150_partial_unsat_classification.json"
OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_101_150_partial_unsat_classification.md"


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
        101: {
            "status": "部分满足",
            "comment": "PUBCOMP 之后同 packet id 的后续 PUBLISH 会被当作新消息处理；但 QoS2 去重状态机并不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3375",
                "wolfMQTT-master/src/mqtt_broker.c:3562",
            ],
            "category": "QoS2 去重状态机覆盖不完整",
            "risk_level": "high",
            "reason": "实现按当前包直接处理并回包，缺少完整 QoS2 入站去重状态管理。",
        },
        102: {
            "status": "部分满足",
            "comment": "Broker 端 packet id 为递增分配并跳过 0，但未校验“当前未使用集合”；Client 端由调用方提供 id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1628",
                "wolfMQTT-master/src/mqtt_broker.c:1633",
                "wolfMQTT-master/src/mqtt_broker.c:3302",
                "wolfMQTT-master/src/mqtt_client.c:2169",
            ],
            "category": "Packet Identifier 唯一值分配校验不足",
            "risk_level": "high",
            "reason": "缺少 in-use 集合冲突检测，无法强保证“从未使用值集合选择”。",
        },
        103: {
            "status": "满足",
            "comment": "UNSUBACK 的 packet id 直接来自对应 UNSUBSCRIBE。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3161",
                "wolfMQTT-master/src/mqtt_packet.c:2319",
            ],
        },
        104: {
            "status": "满足",
            "comment": "收到 PUBREL 后发送 PUBCOMP，沿用同一个 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3375",
                "wolfMQTT-master/src/mqtt_broker.c:3389",
                "wolfMQTT-master/src/mqtt_broker.c:3392",
            ],
        },
        105: {
            "status": "满足",
            "comment": "收到 PUBREC 后发送 PUBREL，沿用同一个 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3411",
                "wolfMQTT-master/src/mqtt_broker.c:3425",
                "wolfMQTT-master/src/mqtt_broker.c:3428",
            ],
        },
        106: {
            "status": "满足",
            "comment": "SUBACK 的 packet id 来自已解析的 SUBSCRIBE。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3111",
                "wolfMQTT-master/src/mqtt_broker.c:2623",
            ],
        },
        107: {
            "status": "部分满足",
            "comment": "QoS1 新消息会分配 packet id，但分配策略缺少“当前未使用”校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3300",
                "wolfMQTT-master/src/mqtt_broker.c:3302",
                "wolfMQTT-master/src/mqtt_broker.c:1628",
                "wolfMQTT-master/src/mqtt_broker.c:1633",
            ],
            "category": "Packet Identifier 唯一值分配校验不足",
            "risk_level": "high",
            "reason": "仅递增与回绕，未做在用冲突检查。",
        },
        108: {
            "status": "满足",
            "comment": "QoS1 入站 PUBLISH 回 PUBACK 时，packet id 复制自入站包。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3342",
                "wolfMQTT-master/src/mqtt_client.c:964",
            ],
        },
        109: {
            "status": "满足",
            "comment": "QoS1 发送 PUBLISH 时要求并编码 packet id（非 0）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1363",
            ],
        },
        110: {
            "status": "满足",
            "comment": "QoS2 入站 PUBLISH 回 PUBREC 时，packet id 复制自入站包。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3343",
                "wolfMQTT-master/src/mqtt_client.c:965",
            ],
        },
        111: {
            "status": "部分满足",
            "comment": "QoS2 新消息分配 packet id，但未建立“未使用集合”唯一性约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3300",
                "wolfMQTT-master/src/mqtt_broker.c:3302",
                "wolfMQTT-master/src/mqtt_broker.c:1628",
                "wolfMQTT-master/src/mqtt_broker.c:1633",
            ],
            "category": "Packet Identifier 唯一值分配校验不足",
            "risk_level": "high",
            "reason": "QoS2 分配路径同样缺少在用冲突检测。",
        },
        112: {
            "status": "满足",
            "comment": "QoS2 发送 PUBLISH 时要求并编码 packet id（非 0）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1363",
            ],
        },
        113: {
            "status": "满足",
            "comment": "发送 PUBREL（响应 PUBREC）时沿用相同 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3411",
                "wolfMQTT-master/src/mqtt_broker.c:3425",
            ],
        },
        114: {
            "status": "满足",
            "comment": "SUBACK 变量头 packet id 源自对应 SUBSCRIBE。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3111",
                "wolfMQTT-master/src/mqtt_broker.c:2623",
            ],
        },
        115: {
            "status": "满足",
            "comment": "UNSUBACK 变量头 packet id 源自对应 UNSUBSCRIBE。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3161",
                "wolfMQTT-master/src/mqtt_packet.c:2319",
            ],
        },
        116: {
            "status": "不满足",
            "comment": "未实现 Method B 的“discard packet identifier”显式状态迁移。",
            "evidence": [
                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:194",
                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:321",
                "wolfMQTT-master/src/mqtt_broker.c:3556",
                "wolfMQTT-master/src/mqtt_broker.c:3568",
            ],
            "category": "QoS2 Method B 存储/丢弃流程缺失",
            "risk_level": "high",
            "reason": "Broker 客户端状态结构中无对应 Method B 去重/丢弃状态存储。",
        },
        117: {
            "status": "不满足",
            "comment": "未发现 Method B 接收端 packet identifier 持久化存储与比对逻辑。",
            "evidence": [
                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:194",
                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:262",
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3335",
            ],
            "category": "QoS2 Method B 存储/丢弃流程缺失",
            "risk_level": "high",
            "reason": "接收 QoS2 PUBLISH 后无对应 packet id 去重缓存。",
        },
        118: {
            "status": "不满足",
            "comment": "未实现 Method B 流程里与 packet identifier 相关的存储/丢弃闭环。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3411",
                "wolfMQTT-master/src/mqtt_broker.c:3425",
                "wolfMQTT-master/src/mqtt_broker.c:3566",
                "wolfMQTT-master/wolfmqtt/mqtt_broker.h:194",
            ],
            "category": "QoS2 Method B 存储/丢弃流程缺失",
            "risk_level": "high",
            "reason": "流程仅做即时应答，缺少 Method B 语义化状态机。",
        },
        119: {
            "status": "满足",
            "comment": "QoS0 PUBLISH 不编码 packet id，解码也仅在 QoS>0 时读取。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1362",
                "wolfMQTT-master/src/mqtt_packet.c:1443",
            ],
        },
        120: {
            "status": "满足",
            "comment": "SUBACK 使用与 SUBSCRIBE 相同的 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3111",
                "wolfMQTT-master/src/mqtt_broker.c:2623",
            ],
        },
        121: {
            "status": "部分满足",
            "comment": "发送路径对 SUBSCRIBE/UNSUBSCRIBE/PUBLISH(QoS>0) 已做 non-zero 校验；接收解码路径未统一校验 non-zero。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1715",
                "wolfMQTT-master/src/mqtt_packet.c:2010",
                "wolfMQTT-master/src/mqtt_packet.c:1449",
                "wolfMQTT-master/src/mqtt_packet.c:1828",
                "wolfMQTT-master/src/mqtt_packet.c:2117",
            ],
            "category": "Packet Identifier 非零约束接收校验不足",
            "risk_level": "high",
            "reason": "发送端严格，接收端对非零约束未完全落地。",
        },
        122: {
            "status": "满足",
            "comment": "UNSUBACK 对应 UNSUBSCRIBE 的 packet id 保持一致。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3161",
                "wolfMQTT-master/src/mqtt_packet.c:2319",
            ],
        },
        123: {
            "status": "部分满足",
            "comment": "收到同 packet id 的后续 QoS2 PUBLISH 时会按当前包回 PUBREC；但“直到收到对应 PUBREL”的去重状态约束不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3561",
                "wolfMQTT-master/src/mqtt_broker.c:3564",
            ],
            "category": "QoS2 去重状态机覆盖不完整",
            "risk_level": "high",
            "reason": "缺少“等待 PUBREL 期间”去重状态，可能重复分发。",
        },
        124: {
            "status": "不满足",
            "comment": "clean_session=0 重连后仅保留订阅，不会自动重发未确认 PUBLISH/PUBREL。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1397",
                "wolfMQTT-master/src/mqtt_broker.c:2777",
                "wolfMQTT-master/src/mqtt_client.c:3031",
                "wolfMQTT-master/src/mqtt_client.c:3042",
            ],
            "category": "CleanSession=0 重连重传机制缺失",
            "risk_level": "high",
            "reason": "重连语义缺失 inflight 重放，无法满足该规则要求。",
        },
        125: {
            "status": "不满足",
            "comment": "未实现“重连时未确认 PUBLISH/PUBREL 复用原 packet id 并重发”的自动机制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3497",
                "wolfMQTT-master/src/mqtt_broker.c:3581",
                "wolfMQTT-master/src/mqtt_client.c:3031",
                "wolfMQTT-master/src/mqtt_client.c:3042",
            ],
            "category": "CleanSession=0 重连重传机制缺失",
            "risk_level": "high",
            "reason": "实现重点在订阅会话延续，不包含未确认消息重放队列。",
        },
        126: {
            "status": "满足",
            "comment": "响应 PUBREL 发送 PUBCOMP 时使用同一 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3375",
                "wolfMQTT-master/src/mqtt_broker.c:3390",
            ],
        },
        127: {
            "status": "满足",
            "comment": "响应入站 PUBLISH 的 PUBACK 使用原 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3342",
            ],
        },
        128: {
            "status": "满足",
            "comment": "PUBCOMP 发送流程沿用已跟踪的 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3389",
                "wolfMQTT-master/src/mqtt_broker.c:3392",
            ],
        },
        129: {
            "status": "部分满足",
            "comment": "ACK 处理后会移除等待响应记录，但 packet id 复用策略依赖调用方/递增器，非显式 in-use 集合管理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_client.c:2287",
                "wolfMQTT-master/src/mqtt_client.c:2297",
                "wolfMQTT-master/src/mqtt_client.c:3042",
                "wolfMQTT-master/src/mqtt_broker.c:1628",
            ],
            "category": "Packet Identifier 释放后复用策略不完整",
            "risk_level": "medium",
            "reason": "有“处理后可继续使用”的效果，但缺少统一复用分配约束。",
        },
        130: {
            "status": "部分满足",
            "comment": "发送新包时未统一保证“当前未使用值”；仅有 non-zero 或递增分配。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_client.c:2169",
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_broker.c:1628",
                "wolfMQTT-master/src/mqtt_broker.c:1633",
            ],
            "category": "Packet Identifier 唯一值分配校验不足",
            "risk_level": "high",
            "reason": "缺少端到端“发送前未占用校验”。",
        },
        131: {
            "status": "满足",
            "comment": "PUBACK/PUBREC/PUBREL 路径中 packet id 与对应 PUBLISH 保持一致。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_client.c:964",
                "wolfMQTT-master/src/mqtt_client.c:1000",
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3425",
            ],
        },
        132: {
            "status": "满足",
            "comment": "SUBACK/UNSUBACK 与请求包 packet id 一一对应。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3111",
                "wolfMQTT-master/src/mqtt_broker.c:3161",
                "wolfMQTT-master/src/mqtt_client.c:1305",
            ],
        },
        133: {
            "status": "部分满足",
            "comment": "字段存在性满足；但接收端对 non-zero 的协议约束校验不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1715",
                "wolfMQTT-master/src/mqtt_packet.c:2010",
                "wolfMQTT-master/src/mqtt_packet.c:1828",
                "wolfMQTT-master/src/mqtt_packet.c:2117",
            ],
            "category": "Packet Identifier 非零约束接收校验不足",
            "risk_level": "high",
            "reason": "编码侧强约束与解码侧弱约束不一致。",
        },
        134: {
            "status": "部分满足",
            "comment": "重发时可由调用方复用同 packet id，但库内未形成通用自动重发同 id 的强约束机制。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_client.c:2169",
                "wolfMQTT-master/src/mqtt_client.c:2287",
                "wolfMQTT-master/src/mqtt_client.c:2910",
                "wolfMQTT-master/src/mqtt_client.c:3042",
            ],
            "category": "Packet Identifier 重传同值约束覆盖不完整",
            "risk_level": "medium",
            "reason": "行为可实现但依赖调用方策略，缺少内建保障。",
        },
        135: {
            "status": "满足",
            "comment": "QoS1/2 PUBLISH 均要求并携带 packet id。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1363",
                "wolfMQTT-master/src/mqtt_packet.c:1443",
            ],
        },
        136: {
            "status": "满足",
            "comment": "PUBACK 的 packet id 来源于已确认的 PUBLISH。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3342",
            ],
        },
        137: {
            "status": "满足",
            "comment": "PUBREC 的 packet id 来源于已确认的 PUBLISH。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3335",
                "wolfMQTT-master/src/mqtt_broker.c:3343",
            ],
        },
        138: {
            "status": "部分满足",
            "comment": "Server 发送 QoS>0 PUBLISH 时会分配 packet id，但未做 in-use 冲突检查。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3302",
                "wolfMQTT-master/src/mqtt_broker.c:1628",
                "wolfMQTT-master/src/mqtt_broker.c:1633",
                "wolfMQTT-master/src/mqtt_broker.c:3650",
            ],
            "category": "Packet Identifier 唯一值分配校验不足",
            "risk_level": "high",
            "reason": "服务端侧同样缺少“当前未使用值”校验闭环。",
        },
        139: {
            "status": "部分满足",
            "comment": "编码路径可保证 Password Flag=0 时不发送密码字段；但解码后未校验 payload 消费完毕，异常组合可能未被显式拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:886",
                "wolfMQTT-master/src/mqtt_packet.c:940",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Password Flag=0 负载一致性校验不足",
            "risk_level": "medium",
            "reason": "发送端约束存在，接收端一致性校验不足。",
        },
        140: {
            "status": "部分满足",
            "comment": "同 ID139：Password Flag=0 的异常负载一致性校验未完全闭环。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:886",
                "wolfMQTT-master/src/mqtt_packet.c:940",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Password Flag=0 负载一致性校验不足",
            "risk_level": "medium",
            "reason": "缺少对“Flag=0 但携带密码载荷”场景的显式协议拒绝。",
        },
        141: {
            "status": "满足",
            "comment": "Password Flag=1 时会按协议解析密码字段；缺失时解码失败。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1134",
            ],
        },
        142: {
            "status": "满足",
            "comment": "同 ID141：Password Flag=1 对应密码字段读取路径存在且有边界检查。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1136",
            ],
        },
        143: {
            "status": "部分满足",
            "comment": "编码路径保证 Password 与 Username 联动；接收端未显式校验全部联动约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:774",
                "wolfMQTT-master/src/mqtt_packet.c:777",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
            ],
            "category": "Password/Username Flag 联动校验不足",
            "risk_level": "medium",
            "reason": "发送端做了强约束，接收端未完整实现同等级协议校验。",
        },
        144: {
            "status": "满足",
            "comment": "Password 字段长度使用 16-bit 并进行边界校验（0..65535）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:338",
                "wolfMQTT-master/src/mqtt_packet.c:346",
                "wolfMQTT-master/src/mqtt_packet.c:366",
                "wolfMQTT-master/src/mqtt_packet.c:370",
            ],
        },
        145: {
            "status": "满足",
            "comment": "实现使用 CONNACK 0x04 表示用户名/密码相关校验失败（长度/认证失败）。",
            "evidence": [
                "wolfMQTT-master/wolfmqtt/mqtt_packet.h:390",
                "wolfMQTT-master/src/mqtt_broker.c:2877",
                "wolfMQTT-master/src/mqtt_broker.c:2905",
                "wolfMQTT-master/src/mqtt_broker.c:2960",
            ],
        },
        146: {
            "status": "部分满足",
            "comment": "Password Flag=0 的主要语义路径成立，但接收端对异常负载一致性的显式拒绝不足。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1145",
            ],
            "category": "Password Flag=0 负载一致性校验不足",
            "risk_level": "medium",
            "reason": "以“是否读取字段”替代了“协议一致性强校验”。",
        },
        147: {
            "status": "满足",
            "comment": "Password Flag=1 时会进入密码字段解析，字段缺失会触发解码错误。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1130",
                "wolfMQTT-master/src/mqtt_packet.c:1134",
            ],
        },
        148: {
            "status": "部分满足",
            "comment": "编码端已实现 User Name Flag=0 时 Password 不允许存在；接收端未显式拒绝所有违规 flag 组合。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:774",
                "wolfMQTT-master/src/mqtt_packet.c:777",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
            ],
            "category": "CONNECT Flags 交叉约束接收校验不足",
            "risk_level": "high",
            "reason": "客户端编码强约束已实现，但 broker 解码路径缺失对违规组合的协议级拒绝。",
        },
        149: {
            "status": "部分满足",
            "comment": "Password Flag=1 的字段顺序处理存在，但与 Username/Password 联动一致性校验不完全。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:938",
                "wolfMQTT-master/src/mqtt_packet.c:941",
                "wolfMQTT-master/src/mqtt_packet.c:1118",
                "wolfMQTT-master/src/mqtt_packet.c:1130",
            ],
            "category": "Password/Username Flag 联动校验不足",
            "risk_level": "medium",
            "reason": "顺序正确但联动约束在接收端并未完整硬化。",
        },
        150: {
            "status": "不满足",
            "comment": "SUBSCRIBE 解码允许空 payload（topic_count=0），且该异常处理未形成规范化拒绝闭环。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1865",
                "wolfMQTT-master/src/mqtt_packet.c:1898",
                "wolfMQTT-master/src/mqtt_broker.c:2603",
                "wolfMQTT-master/src/mqtt_broker.c:3111",
                "wolfMQTT-master/src/mqtt_broker.c:3571",
            ],
            "category": "SUBSCRIBE Payload 最小元素约束缺失",
            "risk_level": "high",
            "reason": "未落实“至少一个 Topic Filter/QoS 对”约束。",
        },
    }


def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:
    results: list[dict] = []
    for i, change in enumerate(changes, start=101):
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
        "scope": "source_changes_index_100_to_149",
        "display_scope": "101-150",
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
        "# wolfMQTT-master 101-150 对比结果",
        "",
        f"- 对比输入: `output/02_variable_changes.json` 的索引 `100..149`（共 {len(rows)} 条）",
        "- 目标代码: `wolfMQTT-master`",
        f"- 满足: {meta['counts']['满足']}",
        f"- 部分满足: {meta['counts']['部分满足']}",
        f"- 不满足: {meta['counts']['不满足']}",
        f"- 不适用: {meta['counts']['不适用']}",
        f"- 待确认: {meta['counts']['待确认']}",
        (
            "- 证据定位校验: "
            f"all_locatable={meta['evidence_validation']['all_locatable']}, "
            f"references={meta['evidence_validation']['total_references']}"
        ),
        "",
        "| ID | source_idx | variable | action | 状态 | 说明 | 证据数 |",
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
        "scope": "wolfMQTT-master 101-150 partial+unsatisfied",
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
        "# wolfMQTT-master 101-150 未满足/部分满足分类",
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
            "| ID | source_idx | 状态 | 风险 | 分类 | 说明 |",
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
    changes = source.get("changes", [])[100:150]
    if len(changes) != 50:
        raise RuntimeError(f"Expected 50 items for 101-150, got {len(changes)}")

    mapping = rule_mapping()
    if sorted(mapping.keys()) != list(range(101, 151)):
        raise RuntimeError("Rule mapping must cover IDs 101..150")

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
