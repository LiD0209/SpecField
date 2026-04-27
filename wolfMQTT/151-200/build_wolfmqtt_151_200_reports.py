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

OUT_COMPARE_JSON = OUT_DIR / "compare_wolfmqtt_151_200.json"
OUT_COMPARE_MD = OUT_DIR / "compare_wolfmqtt_151_200.md"
OUT_SIMPLE_TXT = OUT_DIR / "compare_wolfmqtt_151_200_simple.txt"
OUT_CLASS_JSON = OUT_DIR / "compare_wolfmqtt_151_200_partial_unsat_classification.json"
OUT_CLASS_MD = OUT_DIR / "compare_wolfmqtt_151_200_partial_unsat_classification.md"


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
        151: {
            "status": "不满足",
            "comment": "UNSUBSCRIBE 解码允许空 payload（topic_count=0），未落实“至少一个 Topic Filter”约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2091",
                "wolfMQTT-master/src/mqtt_packet.c:2154",
                "wolfMQTT-master/src/mqtt_packet.c:2181",
                "wolfMQTT-master/src/mqtt_broker.c:3141",
            ],
            "category": "SUBSCRIBE/UNSUBSCRIBE 最小 payload 约束缺失",
            "risk_level": "high",
            "reason": "协议要求最小元素时，当前实现可接受空载荷。",
        },
        152: {
            "status": "不满足",
            "comment": "Broker 接收 DISCONNECT 时按包类型直接处理，未校验 Remaining Length/payload 是否为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3509",
                "wolfMQTT-master/src/mqtt_broker.c:3579",
                "wolfMQTT-master/src/mqtt_broker.c:3588",
            ],
            "category": "PINGREQ/DISCONNECT 空 payload 校验缺失",
            "risk_level": "high",
            "reason": "接收路径缺少协议格式校验。",
        },
        153: {
            "status": "不满足",
            "comment": "Broker 接收 PINGREQ 时未验证 Remaining Length 是否为 0，直接回复 PINGRESP。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3509",
                "wolfMQTT-master/src/mqtt_broker.c:3576",
                "wolfMQTT-master/src/mqtt_broker.c:2591",
            ],
            "category": "PINGREQ/DISCONNECT 空 payload 校验缺失",
            "risk_level": "high",
            "reason": "没有“非法长度即协议错误”的分支。",
        },
        154: {
            "status": "部分满足",
            "comment": "发送侧 PINGRESP 为固定头+0 长度；接收侧 PINGRESP 解码未强制 remain_len=0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:2591",
                "wolfMQTT-master/src/mqtt_broker.c:2592",
                "wolfMQTT-master/src/mqtt_packet.c:2389",
                "wolfMQTT-master/src/mqtt_packet.c:2400",
            ],
            "category": "控制报文空 payload 接收校验不足",
            "risk_level": "medium",
            "reason": "编码符合，解码校验偏宽松。",
        },
        155: {
            "status": "部分满足",
            "comment": "PUBCOMP 编码在 MQTT 3.x 下仅 packet id（remain_len=2）；解码未严格限制为恰好 2。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1533",
                "wolfMQTT-master/src/mqtt_packet.c:1563",
                "wolfMQTT-master/src/mqtt_packet.c:1632",
                "wolfMQTT-master/src/mqtt_broker.c:3390",
            ],
            "category": "ACK 报文长度严格校验不足",
            "risk_level": "medium",
            "reason": "存在“至少 2 字节”校验，但无 MQTT3 严格等值校验。",
        },
        156: {
            "status": "部分满足",
            "comment": "PUBREL 编码在 MQTT 3.x 下仅 packet id（remain_len=2）；解码未严格限制为恰好 2。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1533",
                "wolfMQTT-master/src/mqtt_packet.c:1563",
                "wolfMQTT-master/src/mqtt_packet.c:1632",
                "wolfMQTT-master/src/mqtt_broker.c:3426",
            ],
            "category": "ACK 报文长度严格校验不足",
            "risk_level": "medium",
            "reason": "接收端未对 MQTT3 场景做固定长度强校验。",
        },
        157: {
            "status": "满足",
            "comment": "UNSUBACK 在 MQTT 3.x 编码仅包含 packet id，不包含 payload。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2280",
                "wolfMQTT-master/src/mqtt_packet.c:2308",
                "wolfMQTT-master/src/mqtt_packet.c:2319",
            ],
        },
        158: {
            "status": "不满足",
            "comment": "SUBSCRIBE 解码允许 topic_count=0，空 payload 未在解码层判为非法。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1865",
                "wolfMQTT-master/src/mqtt_packet.c:1898",
                "wolfMQTT-master/src/mqtt_broker.c:3066",
                "wolfMQTT-master/src/mqtt_broker.c:3111",
            ],
            "category": "SUBSCRIBE/UNSUBSCRIBE 最小 payload 约束缺失",
            "risk_level": "high",
            "reason": "最小元素约束未在协议接收面落实。",
        },
        159: {
            "status": "满足",
            "comment": "PUBLISH payload 长度按 Remaining Length 减去 variable header 长度计算。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1497",
                "wolfMQTT-master/src/mqtt_packet.c:1500",
                "wolfMQTT-master/src/mqtt_packet.c:1505",
            ],
        },
        160: {
            "status": "满足",
            "comment": "RETAIN=1 且 payload 长度为 0 时执行删除，不会存储零字节 retained 消息。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3251",
                "wolfMQTT-master/src/mqtt_broker.c:3252",
                "wolfMQTT-master/src/mqtt_broker.c:3267",
            ],
        },
        161: {
            "status": "满足",
            "comment": "实现了“retained + payload=0 => 删除 retained message”的行为。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3252",
                "wolfMQTT-master/src/mqtt_broker.c:3253",
                "wolfMQTT-master/src/mqtt_broker.c:2456",
            ],
        },
        162: {
            "status": "部分满足",
            "comment": "PUBACK 编码无 payload；解码侧仅校验 remain_len>=2，未做 MQTT3 固定长度严格校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1533",
                "wolfMQTT-master/src/mqtt_packet.c:1632",
                "wolfMQTT-master/src/mqtt_broker.c:3342",
            ],
            "category": "ACK 报文长度严格校验不足",
            "risk_level": "medium",
            "reason": "接收容忍更长报文，严格性不足。",
        },
        163: {
            "status": "部分满足",
            "comment": "PUBREC 编码无 payload；解码侧同样未做 MQTT3 固定长度严格校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1533",
                "wolfMQTT-master/src/mqtt_packet.c:1632",
                "wolfMQTT-master/src/mqtt_broker.c:3343",
            ],
            "category": "ACK 报文长度严格校验不足",
            "risk_level": "medium",
            "reason": "缺少“长度必须等于 2”的约束。",
        },
        164: {
            "status": "满足",
            "comment": "PUBLISH payload 支持 0 长度并有边界处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1500",
                "wolfMQTT-master/src/mqtt_packet.c:1505",
                "wolfMQTT-master/src/mqtt_broker.c:3278",
            ],
        },
        165: {
            "status": "部分满足",
            "comment": "编码侧满足 QoS>0 才携带 packet id 且非 0；解码侧未校验 packet id 非 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1362",
                "wolfMQTT-master/src/mqtt_packet.c:1443",
                "wolfMQTT-master/src/mqtt_packet.c:1449",
            ],
            "category": "QoS 与 Packet Identifier 联动校验不完整",
            "risk_level": "high",
            "reason": "发送端约束强，接收端 non-zero 缺失。",
        },
        166: {
            "status": "满足",
            "comment": "下行转发 QoS 按 min(发布 QoS, 订阅 QoS) 计算。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3299",
                "wolfMQTT-master/src/mqtt_broker.c:3300",
                "wolfMQTT-master/src/mqtt_broker.c:2488",
            ],
        },
        167: {
            "status": "不满足",
            "comment": "未实现 clean_session=0 重连后未确认 PUBLISH 自动重发路径。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1397",
                "wolfMQTT-master/src/mqtt_broker.c:3497",
                "wolfMQTT-master/src/mqtt_client.c:3031",
                "wolfMQTT-master/src/mqtt_client.c:3042",
            ],
            "category": "CleanSession=0 重连重传机制缺失",
            "risk_level": "high",
            "reason": "会话保持主要是订阅层，不含 inflight 消息重传。",
        },
        168: {
            "status": "满足",
            "comment": "QoS0 场景转发时 out_pub.qos 保持为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3299",
                "wolfMQTT-master/src/mqtt_broker.c:3300",
            ],
        },
        169: {
            "status": "部分满足",
            "comment": "QoS1 发送可在路径上实现，但缺少统一强约束防止异常 QoS 值。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3299",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
            ],
            "category": "QoS 固定值与边界校验不完整",
            "risk_level": "medium",
            "reason": "主要流程可达成，协议级硬约束不足。",
        },
        170: {
            "status": "部分满足",
            "comment": "QoS2 发送可在路径上实现，但缺少统一边界与非法值拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3299",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
            ],
            "category": "QoS 固定值与边界校验不完整",
            "risk_level": "medium",
            "reason": "依赖调用路径与上层输入，缺少全面限制。",
        },
        171: {
            "status": "部分满足",
            "comment": "QoS 与 packet id 存在性关系基本成立，但 packet id 非 0 的接收校验缺失。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1308",
                "wolfMQTT-master/src/mqtt_packet.c:1362",
                "wolfMQTT-master/src/mqtt_packet.c:1443",
                "wolfMQTT-master/src/mqtt_packet.c:1449",
            ],
            "category": "QoS 与 Packet Identifier 联动校验不完整",
            "risk_level": "high",
            "reason": "解码侧未拒绝 QoS>0 + packet_id=0。",
        },
        172: {
            "status": "部分满足",
            "comment": "QoS>0 与 packet id 关联存在，但缺少完整的 non-zero 校验闭环。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1309",
                "wolfMQTT-master/src/mqtt_packet.c:1443",
                "wolfMQTT-master/src/mqtt_packet.c:1449",
            ],
            "category": "QoS 与 Packet Identifier 联动校验不完整",
            "risk_level": "high",
            "reason": "发送侧有校验，接收侧无等价校验。",
        },
        173: {
            "status": "满足",
            "comment": "响应订阅转发消息的 QoS 由发布 QoS 与订阅 QoS 推导（取较小值）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3299",
                "wolfMQTT-master/src/mqtt_broker.c:2488",
            ],
        },
        174: {
            "status": "满足",
            "comment": "SUBACK 对每个 topic tuple 返回一个结果码，并对请求 QoS 做上限裁剪。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3073",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
                "wolfMQTT-master/src/mqtt_broker.c:3106",
                "wolfMQTT-master/src/mqtt_broker.c:3111",
            ],
        },
        175: {
            "status": "部分满足",
            "comment": "单订阅/同过滤器更新场景可满足，但重叠订阅“取最大 QoS”语义未形成统一汇总逻辑。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1470",
                "wolfMQTT-master/src/mqtt_broker.c:1478",
                "wolfMQTT-master/src/mqtt_broker.c:3291",
                "wolfMQTT-master/src/mqtt_broker.c:3299",
            ],
            "category": "重叠订阅 QoS 汇总语义不完整",
            "risk_level": "medium",
            "reason": "按匹配项逐条转发，缺少统一“最大 QoS 汇总后单发”机制。",
        },
        176: {
            "status": "不满足",
            "comment": "clean_session=0 重连后的未确认 PUBLISH 重发机制缺失，无法验证该路径下 QoS 约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3497",
                "wolfMQTT-master/src/mqtt_broker.c:3581",
                "wolfMQTT-master/src/mqtt_client.c:3031",
            ],
            "category": "CleanSession=0 重连重传机制缺失",
            "risk_level": "high",
            "reason": "无内建重发通道。",
        },
        177: {
            "status": "部分满足",
            "comment": "QoS0 + DUP 约束未在通用编码接口强校验，主要依赖调用约定。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1343",
                "wolfMQTT-master/src/mqtt_broker.c:3305",
            ],
            "category": "QoS 与 DUP 约束实现不完整",
            "risk_level": "medium",
            "reason": "缺少统一禁止非法组合的入口校验。",
        },
        178: {
            "status": "部分满足",
            "comment": "描述场景可实现指定 QoS，但未建立全局强制约束。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3299",
                "wolfMQTT-master/src/mqtt_packet.c:1343",
            ],
            "category": "QoS 固定值与边界校验不完整",
            "risk_level": "medium",
            "reason": "更偏路径性满足，而非协议级强制。",
        },
        179: {
            "status": "不满足",
            "comment": "SUBSCRIBE 请求 QoS 未做集合校验，options 仅取低 2 位，值 3 会被接受并后续裁剪。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1890",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
                "wolfMQTT-master/src/mqtt_broker.c:3083",
            ],
            "category": "SUBSCRIBE Requested QoS/保留位校验缺失",
            "risk_level": "high",
            "reason": "应在接收面拒绝非法 Requested QoS，而非静默裁剪。",
        },
        180: {
            "status": "不满足",
            "comment": "SUBSCRIBE 中非法 Requested QoS 未触发协议错误断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1890",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
                "wolfMQTT-master/src/mqtt_broker.c:3570",
            ],
            "category": "SUBSCRIBE Requested QoS/保留位校验缺失",
            "risk_level": "high",
            "reason": "缺少 invalid->disconnect 的强处理分支。",
        },
        181: {
            "status": "满足",
            "comment": "接收 PUBLISH 后的响应类型由 QoS 推导：QoS1->PUBACK，QoS2->PUBREC，QoS0 无应答。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3333",
                "wolfMQTT-master/src/mqtt_broker.c:3342",
                "wolfMQTT-master/src/mqtt_broker.c:3343",
            ],
        },
        182: {
            "status": "部分满足",
            "comment": "存在按订阅 QoS 限幅逻辑，但重叠订阅的全局最大 QoS 汇总语义不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:1478",
                "wolfMQTT-master/src/mqtt_broker.c:3291",
                "wolfMQTT-master/src/mqtt_broker.c:3299",
            ],
            "category": "重叠订阅 QoS 汇总语义不完整",
            "risk_level": "medium",
            "reason": "多匹配订阅缺少统一汇总决策。",
        },
        183: {
            "status": "不满足",
            "comment": "未实现 PUBLISH QoS bits=11 的协议级拒绝与断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:204",
                "wolfMQTT-master/src/mqtt_broker.c:3207",
                "wolfMQTT-master/src/mqtt_broker.c:3333",
            ],
            "category": "PUBLISH QoS bits 非法值校验缺失",
            "risk_level": "high",
            "reason": "QoS=3 可进入处理路径。",
        },
        184: {
            "status": "不满足",
            "comment": "PUBLISH 不允许的 QoS bits 组合（11）未被拒绝。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:204",
                "wolfMQTT-master/src/mqtt_packet.c:1426",
            ],
            "category": "PUBLISH QoS bits 非法值校验缺失",
            "risk_level": "high",
            "reason": "固定头解析不校验 qos bits 合法性。",
        },
        185: {
            "status": "不满足",
            "comment": "同 ID183：收到 QoS bits=11 的 PUBLISH 时未断链。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:204",
                "wolfMQTT-master/src/mqtt_broker.c:3537",
                "wolfMQTT-master/src/mqtt_broker.c:3550",
            ],
            "category": "PUBLISH QoS bits 非法值校验缺失",
            "risk_level": "high",
            "reason": "缺少协议违规断开分支。",
        },
        186: {
            "status": "不满足",
            "comment": "同 ID184：forbidden QoS bits 组合未在接收侧判为非法。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:204",
                "wolfMQTT-master/src/mqtt_packet.c:1426",
            ],
            "category": "PUBLISH QoS bits 非法值校验缺失",
            "risk_level": "high",
            "reason": "缺少 QoS bits=3 的接收拒绝逻辑。",
        },
        187: {
            "status": "满足",
            "comment": "Remaining Length 编解码有上限控制：编码限制最大值，解码限制最多 4 字节。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:264",
                "wolfMQTT-master/src/mqtt_packet.c:236",
                "wolfMQTT-master/src/mqtt_packet.c:2957",
            ],
        },
        188: {
            "status": "部分满足",
            "comment": "读取路径按 Remaining Length 驱动，但当报文大于接收缓冲区时会截断读取，严格一致性校验不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:2984",
                "wolfMQTT-master/src/mqtt_packet.c:2991",
                "wolfMQTT-master/src/mqtt_packet.c:2992",
                "wolfMQTT-master/src/mqtt_packet.c:3012",
            ],
            "category": "Remaining Length 一致性校验不完整",
            "risk_level": "medium",
            "reason": "存在分段/截断场景，未统一在此层强制“全部剩余字节都在当前包”。",
        },
        189: {
            "status": "满足",
            "comment": "CONNECT 的 Remaining Length 由各字段长度累加计算后编码。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:782",
                "wolfMQTT-master/src/mqtt_packet.c:804",
                "wolfMQTT-master/src/mqtt_packet.c:846",
                "wolfMQTT-master/src/mqtt_packet.c:851",
            ],
        },
        190: {
            "status": "满足",
            "comment": "PUBLISH payload 长度按 Remaining Length 计算得到。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1497",
                "wolfMQTT-master/src/mqtt_packet.c:1500",
            ],
        },
        191: {
            "status": "满足",
            "comment": "PUBACK 在 MQTT 3.x 发送路径 Remaining Length 为常量 2。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1533",
                "wolfMQTT-master/src/mqtt_broker.c:3342",
            ],
        },
        192: {
            "status": "满足",
            "comment": "PUBREC 在 MQTT 3.x 发送路径 Remaining Length 为常量 2。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1533",
                "wolfMQTT-master/src/mqtt_broker.c:3343",
            ],
        },
        193: {
            "status": "满足",
            "comment": "Remaining Length 解码循环结束后返回累计解码值。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:231",
                "wolfMQTT-master/src/mqtt_packet.c:241",
                "wolfMQTT-master/src/mqtt_packet.c:245",
            ],
        },
        194: {
            "status": "不满足",
            "comment": "Requested QoS 未严格限制为 {0,1,2}（值 3 被接受后裁剪）。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1890",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
            ],
            "category": "SUBSCRIBE Requested QoS/保留位校验缺失",
            "risk_level": "high",
            "reason": "未实现集合成员校验。",
        },
        195: {
            "status": "不满足",
            "comment": "Requested QoS 非法时未作为协议错误断开连接。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1890",
                "wolfMQTT-master/src/mqtt_broker.c:3080",
                "wolfMQTT-master/src/mqtt_broker.c:3570",
            ],
            "category": "SUBSCRIBE Requested QoS/保留位校验缺失",
            "risk_level": "high",
            "reason": "invalid 值被容忍并继续处理。",
        },
        196: {
            "status": "部分满足",
            "comment": "服务端有授权 QoS 选择与失败码路径，但策略以“裁剪/回显”为主，协商语义覆盖不完整。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_broker.c:3080",
                "wolfMQTT-master/src/mqtt_broker.c:3083",
                "wolfMQTT-master/src/mqtt_broker.c:3089",
                "wolfMQTT-master/src/mqtt_broker.c:3106",
            ],
            "category": "订阅 QoS 协商语义不完整",
            "risk_level": "medium",
            "reason": "缺少更细粒度授权/拒绝策略。",
        },
        197: {
            "status": "不满足",
            "comment": "固定头 reserved bits 未按报文类型表做合法值校验。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:202",
                "wolfMQTT-master/src/mqtt_packet.c:204",
            ],
            "category": "Fixed Header Reserved bits 校验缺失",
            "risk_level": "high",
            "reason": "仅校验 packet type，未校验 flags 合法性。",
        },
        198: {
            "status": "不满足",
            "comment": "DISCONNECT reserved bits 非 0 场景未实现显式 invalid->disconnect 校验分支。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:202",
                "wolfMQTT-master/src/mqtt_broker.c:3579",
                "wolfMQTT-master/src/mqtt_broker.c:3588",
            ],
            "category": "Fixed Header Reserved bits 校验缺失",
            "risk_level": "high",
            "reason": "接收侧未对 DISCONNECT flags 做合法性验证。",
        },
        199: {
            "status": "不满足",
            "comment": "SUBSCRIBE 的 Requested QoS 字节高 6 位保留位未校验为 0。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:1889",
                "wolfMQTT-master/src/mqtt_packet.c:1890",
            ],
            "category": "SUBSCRIBE Requested QoS/保留位校验缺失",
            "risk_level": "high",
            "reason": "当前仅提取低 2 位 QoS。",
        },
        200: {
            "status": "不满足",
            "comment": "reserved bits 非法值缺少统一 invalid->disconnect 处理。",
            "evidence": [
                "wolfMQTT-master/src/mqtt_packet.c:198",
                "wolfMQTT-master/src/mqtt_packet.c:202",
                "wolfMQTT-master/src/mqtt_broker.c:3537",
            ],
            "category": "Fixed Header Reserved bits 校验缺失",
            "risk_level": "high",
            "reason": "协议违规标志位未触发统一拒绝断链。",
        },
    }


def build_compare(changes: list[dict], mapping: dict[int, dict]) -> dict:
    results: list[dict] = []
    for i, change in enumerate(changes, start=151):
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
        "scope": "source_changes_index_150_to_199",
        "display_scope": "151-200",
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
        "# wolfMQTT-master 151-200 对比结果",
        "",
        f"- 对比输入: `output/02_variable_changes.json` 的索引 `150..199`（共 {len(rows)} 条）",
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
        "scope": "wolfMQTT-master 151-200 partial+unsatisfied",
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
        "# wolfMQTT-master 151-200 未满足/部分满足分类",
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
    changes = source.get("changes", [])[150:200]
    if len(changes) != 50:
        raise RuntimeError(f"Expected 50 items for 151-200, got {len(changes)}")

    mapping = rule_mapping()
    if sorted(mapping.keys()) != list(range(151, 201)):
        raise RuntimeError("Rule mapping must cover IDs 151..200")

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
