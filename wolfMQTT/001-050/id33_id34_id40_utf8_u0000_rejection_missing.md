# ID33/ID34/ID40 Analysis: U+0000 UTF-8 String Rejection Is Missing

## Scope

This document describes the following related findings:

| ID | source_idx | Status | Risk | Category | Summary |
|---:|---:|---|---|---|---|
| 33 | 32 | Not satisfied | high | UTF-8 protocol validation missing | The protocol-level rule forbidding the null character is not implemented. |
| 34 | 33 | Not satisfied | high | UTF-8 protocol validation missing | The receive path does not reject `U+0000` and close the connection. |
| 40 | 39 | Not satisfied | high | UTF-8 protocol validation missing | The null-character rule is not enforced for `ClientId`. |

Checked materials:

- Standard: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`
- Codebase: `D:\project\conditionFuzzing\wolfMQTT-master`
- Repro scripts:
  - `D:\project\conditionFuzzing\wolfMQTT\001-050\repro_id29_40_utf8_test.py`
  - `D:\project\conditionFuzzing\wolfMQTT\001-050\run_id29_40_utf8_test.sh`

## English Standard Text

The relevant MQTT 3.1.1 rule is in Section `1.5.3 UTF-8 encoded strings`, clause `[MQTT-1.5.3-2]`.

Original English text with context:

```text
A UTF-8 encoded string MUST NOT include an encoding of the null character
U+0000.

If a receiver (Server or Client) receives a Control Packet containing U+0000
it MUST close the Network Connection [MQTT-1.5.3-2].
```

Meaning in this issue:

- This is not only a C-string terminator concern. It is a MQTT protocol rule.
- Any MQTT UTF-8 encoded string containing `U+0000` is invalid.
- The required receiver behavior is connection close, not silent acceptance.

There is also a topic-specific rule in Section `4.7.3 Topic semantic and usage`, clause `[MQTT-4.7.3-2]`.

Original English text:

```text
Topic Names and Topic Filters MUST NOT include the null character
(Unicode U+0000) [MQTT-4.7.3-2].
```

The ClientId rule also applies because `[MQTT-3.1.3-4]` requires ClientId to be a UTF-8 encoded string as defined in Section `1.5.3`.

## Code Description

### 1. Shared string decoder preserves raw `0x00`

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_String()`

Relevant code:

```c
len = MqttDecode_Num(buf, &str_len, buf_len);
if (len < 0) {
    return len;
}
if ((word32)str_len > buf_len - (word32)len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
buf += len;
if (pstr) {
    *pstr = (char*)buf;
}
return len + str_len;
```

The decoder does not scan the string bytes. Therefore, a byte sequence such as `41 00 42` (`A`, `U+0000`, `B`) is accepted as a valid MQTT string if the length field is correct.

### 2. ClientId receives no later null-character validation

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Connect()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &mc_connect->client_id, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
if (tmp < 0) {
    return tmp;
}
```

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

The broker stores the decoded ClientId. There is no explicit check for `U+0000` before sending CONNACK success.

### 3. Topic filters receive no null-character validation

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Subscribe()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &topic->topic_filter, NULL,
        (word32)(rx_end - rx_payload));
if (tmp < 0) {
    return tmp;
}
```

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Subscribe()`

Relevant code:

```c
rc = MqttDecode_Subscribe(bc->rx_buf, rx_len, &sub);
if (rc < 0) {
    return rc;
}
...
int sub_rc = BrokerSubs_Add(broker, bc, f, flen, topic_qos);
```

The broker registers the subscription after decode. The `U+0000` rule is not enforced before subscription storage or SUBACK generation.

## Dynamic Test Evidence

The repro script sends MQTT 3.1.1 packets containing `U+0000` in UTF-8 string fields:

- `connect_clientid_u0000`: ClientId bytes `41 00 42`
- `subscribe_topic_u0000`: topic filter bytes `74 2F 00 41`

Observed results:

```text
connect_clientid_u0000 -> CONNACK 20020000, return_code=0, PINGRESP d000
subscribe_topic_u0000 -> SUBACK 9003000700, return_codes=[0], PINGRESP d000
```

The broker accepts both packets and keeps the connection alive.

## Inconsistency Reason

The standard treats `U+0000` as a forbidden character in MQTT UTF-8 encoded strings and requires the receiver to close the network connection. The implementation only validates the MQTT length prefix and buffer boundary. It does not inspect decoded characters or raw UTF-8 bytes for the null character.

This is related to the general UTF-8 validation gap, but it is best tracked separately because `[MQTT-1.5.3-2]` is an independent MUST-level rule with a clear trigger and a clear required action.

## Conclusion

The issue is real.

`ID33`, `ID34`, and `ID40` should be grouped together as one high-risk issue: `U+0000` is accepted in MQTT UTF-8 string fields, including ClientId and Topic Filter, and the required connection close path is missing.
