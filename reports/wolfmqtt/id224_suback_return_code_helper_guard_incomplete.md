# SUBACK Return Code Helper Guard Is Incomplete

## Summary

wolfMQTT's normal broker `SUBACK` construction path usually produces valid MQTT 3.1.1 return codes, but the lower-level broker helper that writes the `SUBACK` packet does not validate the return code bytes it is given.

MQTT 3.1.1 permits only `0x00`, `0x01`, `0x02`, and `0x80` in the `SUBACK` payload. The broker main path sets return codes from granted QoS values or failure, so it normally stays within that set. However, `BrokerSend_SubAck()` writes the caller-provided return code bytes directly into the outgoing packet. If a reserved value reaches this helper, it is sent unchanged.

This is a helper-layer defense gap rather than the main broker path always generating invalid data.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `3.9.3 Payload`, clause `[MQTT-3.9.3-2]`.

Original English requirement:

```text
SUBACK return codes other than 0x00, 0x01, 0x02 and 0x80 are reserved and MUST NOT be used [MQTT-3.9.3-2].
```

Allowed return codes:

| Return Code | Meaning                 |
| ----------: | ----------------------- |
|    `0x00` | Success - Maximum QoS 0 |
|    `0x01` | Success - Maximum QoS 1 |
|    `0x02` | Success - Maximum QoS 2 |
|    `0x80` | Failure                 |

## Expected Behavior

Any code path that constructs a MQTT 3.1.1 `SUBACK` should avoid emitting reserved return codes.

| Helper input return code | Expected helper behavior       |
| -----------------------: | ------------------------------ |
|                 `0x00` | Encode                         |
|                 `0x01` | Encode                         |
|                 `0x02` | Encode                         |
|                 `0x80` | Encode                         |
|                 `0x03` | Reject or normalize to failure |
|                 `0x7F` | Reject or normalize to failure |

## Code Description

### Allowed values are defined

File: `wolfMQTT-master/wolfmqtt/mqtt_packet.h`

Relevant code:

```c
enum MqttSubscribeAckReturnCodes {
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0 = 0,
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS1 = 1,
    MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS2 = 2,
    MQTT_SUBSCRIBE_ACK_CODE_FAILURE = 0x80
};
```

These constants represent the complete MQTT 3.1.1 allowed set.

### Main broker path normally stays within the allowed set

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Subscribe()`

Relevant code:

```c
/* Cap at QoS 2 */
if (topic_qos > MQTT_QOS_2) {
    topic_qos = MQTT_QOS_2;
}
granted_qos = topic_qos;

if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
        &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
    int sub_rc = BrokerSubs_Add(broker, bc, f, flen, topic_qos);
    if (sub_rc != MQTT_CODE_SUCCESS) {
        granted_qos = (MqttQoS)MQTT_SUBSCRIBE_ACK_CODE_FAILURE;
    }
}
return_codes[i] = (byte)granted_qos;
```

This normal path produces `0`, `1`, `2`, or `0x80`. That part is mostly aligned with the standard.

### SUBACK helper writes caller-provided bytes directly

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerSend_SubAck()`

Relevant code:

```c
static int BrokerSend_SubAck(BrokerClient* bc, word16 packet_id,
    const byte* return_codes, int return_code_count)
{
    ...
    bc->tx_buf[pos++] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_SUBSCRIBE_ACK);
    pos += MqttEncode_Vbi(&bc->tx_buf[pos], remain_len);
    pos += MqttEncode_Num(&bc->tx_buf[pos], packet_id);
    ...
    for (i = 0; i < return_code_count; i++) {
        bc->tx_buf[pos++] = return_codes[i];
    }

    return MqttPacket_Write(&bc->client, bc->tx_buf, pos);
}
```

There is no check that `return_codes[i]` belongs to the MQTT 3.1.1 allowed set before it is written to the transmit buffer.

## Inconsistency

The standard says reserved `SUBACK` return codes must not be used. wolfMQTT's main broker path usually avoids them, but the helper that actually serializes the packet does not enforce the rule.

This creates a layered inconsistency:

| Layer                         | Behavior                         |
| ----------------------------- | -------------------------------- |
| Main broker subscription path | Normally produces allowed values |
| SUBACK write helper           | Serializes any byte passed in    |
| Standard requirement          | Reserved values must not be used |

The missing invariant is:

```text
before writing each SUBACK return code:
  verify it is 0x00, 0x01, 0x02, or 0x80
```

## Dynamic Test Evidence

A focused helper test called `BrokerSend_SubAck()` with both valid and reserved return codes while intercepting the bytes written to the network layer.

Observed output:

```text
helper valid code 0x00         rc=5 bytes=90 03 00 01 00
helper valid code 0x80         rc=5 bytes=90 03 00 01 80
helper reserved code 0x03      rc=5 bytes=90 03 00 01 03
helper reserved code 0x7F      rc=5 bytes=90 03 00 01 7F
```

The last byte of the encoded `SUBACK` is the return code. Reserved values `0x03` and `0x7F` are written unchanged.

## Severity

It is less severe than receive-side acceptance of malformed broker responses because the normal broker path already tends to pass allowed values. The risk is that future code paths, helper misuse, unusual error handling, or maintenance changes could pass a reserved value into `BrokerSend_SubAck()` and emit a malformed `SUBACK`.

## Root Cause

The root cause is that SUBACK return code validation is centralized nowhere. The main path constructs mostly valid values, but the serialization helper trusts its input instead of enforcing the protocol's allowed set at the final boundary.

## Suggested Fix Direction

Add a membership check in `BrokerSend_SubAck()` before writing each return code.

One possible approach:

```c
static int MqttSubAckReturnCode_IsValid(byte code)
{
    return code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0 ||
           code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS1 ||
           code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS2 ||
           code == MQTT_SUBSCRIBE_ACK_CODE_FAILURE;
}
```

Then reject or convert invalid helper input before serializing:

```c
if (!MqttSubAckReturnCode_IsValid(return_codes[i])) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would make the helper robust even if a future caller passes a reserved value.
