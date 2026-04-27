# ID31 Analysis: BOM / U+FEFF Semantic Handling Is Not Explicitly Guaranteed

## Scope

This document describes the following finding:

| ID | source_idx | Status | Risk | Category | Summary |
|---:|---:|---|---|---|---|
| 31 | 30 | Partially satisfied | low | UTF-8 semantic guarantee insufficient | The implementation does not appear to strip BOM bytes, but it also has no explicit semantic validation path for `U+FEFF`. |

Checked materials:

- Standard: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`
- Codebase: `D:\project\conditionFuzzing\wolfMQTT-master`
- Repro scripts:
  - `D:\project\conditionFuzzing\wolfMQTT\001-050\repro_id29_40_utf8_test.py`
  - `D:\project\conditionFuzzing\wolfMQTT\001-050\run_id29_40_utf8_test.sh`

## English Standard Text

The relevant MQTT 3.1.1 rule is in Section `1.5.3 UTF-8 encoded strings`, clause `[MQTT-1.5.3-3]`.

Original English text with context:

```text
A UTF-8 encoded sequence 0xEF 0xBB 0xBF is always to be interpreted to
mean U+FEFF ("ZERO WIDTH NO-BREAK SPACE") wherever it appears in a string
and MUST NOT be skipped over or stripped off by a packet receiver
[MQTT-1.5.3-3].
```

Meaning in this issue:

- `EF BB BF` is the UTF-8 byte sequence for `U+FEFF`.
- MQTT says that if this sequence appears anywhere inside a string, the receiver must treat it as the character `U+FEFF`.
- The receiver must not silently remove it, skip it, or treat it as an invisible prefix to discard.
- This rule is different from malformed UTF-8 and `U+0000`: it is not a direct reject-and-close rule; it is a semantic preservation rule.

## Code Description

### 1. Shared string decoder returns raw bytes

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_String()`

Relevant code:

```c
buf += len;
if (pstr_len) {
    *pstr_len = str_len;
}
if (pstr) {
    *pstr = (char*)buf;
}
return len + str_len;
```

This behavior preserves the original byte sequence by returning a pointer into the packet buffer. There is no code here that removes `EF BB BF`.

### 2. Broker stores strings after decode

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
if (rc < 0) {
    return rc;
}
...
BROKER_STORE_STR(bc->client_id, mc.client_id, id_len,
    BROKER_MAX_CLIENT_ID_LEN);
```

The broker stores the decoded byte slice. This means the BOM byte sequence is not intentionally stripped in this path.

## Dynamic Test Evidence

The repro script sends a MQTT 3.1.1 CONNECT with ClientId bytes:

```text
EF BB BF 41
```

Observed result:

```text
connect_clientid_bom_prefix -> CONNACK 20020000, return_code=0, PINGRESP d000
```

This shows the broker accepts a string containing the BOM byte sequence and keeps the connection alive. That behavior is not itself a violation, because `U+FEFF` is not forbidden by `[MQTT-1.5.3-3]`.

## Inconsistency Reason

This finding is weaker than the other UTF-8 issues.

The implementation appears to preserve the raw BOM bytes because it does not transform UTF-8 strings at all. However, it also does not explicitly decode or document that `EF BB BF` is interpreted as `U+FEFF`. The current behavior is therefore a side effect of byte-slice handling rather than an intentional semantic guarantee.

In other words:

- No evidence was found that the receive path strips BOM bytes.
- No evidence was found that the receive path explicitly interprets the sequence as `U+FEFF`.
- The implementation therefore partially satisfies the practical preservation requirement, but lacks an explicit validation or semantic handling path.

## Conclusion

The issue should remain separate and low risk.

`ID31` should not be grouped with the high-risk malformed UTF-8 or `U+0000` rejection failures. It is best described as a semantic assurance gap: the observed behavior preserves BOM bytes, but the implementation does not make the `U+FEFF` rule explicit.
