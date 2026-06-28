# SUBACK Return Code Receive Validation Is Missing

## Summary

wolfMQTT's client-side `SUBACK` decoder accepts reserved MQTT 3.1.1 SUBACK return codes.

In MQTT 3.1.1, each return code in a `SUBACK` payload must be one of `0x00`, `0x01`, `0x02`, or `0x80`. Values such as `0x03` and `0x7F` are reserved and must not be used. wolfMQTT currently copies the received return code bytes into `MqttSubscribeAck.return_codes` without validating membership in the allowed set.

This means a malformed `SUBACK` packet from a broker can be decoded successfully by a wolfMQTT client.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `3.9.3 Payload`, clause `[MQTT-3.9.3-2]`.

Original English requirement:

```text
SUBACK return codes other than 0x00, 0x01, 0x02 and 0x80 are reserved and MUST NOT be used [MQTT-3.9.3-2].
```

The allowed MQTT 3.1.1 values are:

| Return Code | Meaning                 |
| ----------: | ----------------------- |
|    `0x00` | Success - Maximum QoS 0 |
|    `0x01` | Success - Maximum QoS 1 |
|    `0x02` | Success - Maximum QoS 2 |
|    `0x80` | Failure                 |

## Expected Behavior

When decoding a received `SUBACK`, the client should reject any return code outside the allowed MQTT 3.1.1 set.

| Received return code | Expected result |
| -------------------: | --------------- |
|             `0x00` | Accept          |
|             `0x01` | Accept          |
|             `0x02` | Accept          |
|             `0x80` | Accept          |
|             `0x03` | Reject          |
|             `0x7F` | Reject          |

## Code Description

### Constants define only the allowed values

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

The named constants match the four allowed MQTT 3.1.1 return codes.

### Decoder copies return codes without membership validation

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_SubscribeAck()`

Relevant code:

```c
/* payload is list of return codes (MqttSubscribeAckReturnCodes) */
{
    int payload_len = remain_len -
            (int)(rx_payload - &rx_buf[header_len]);
    int buf_remain = rx_buf_len - (int)(rx_payload - rx_buf);
    if (payload_len < 0 || buf_remain < 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    if (payload_len > buf_remain) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    if (payload_len > MAX_MQTT_TOPICS)
        payload_len = MAX_MQTT_TOPICS;
    XMEMSET(subscribe_ack->return_codes, 0, MAX_MQTT_TOPICS);
    XMEMCPY(subscribe_ack->return_codes, rx_payload, payload_len);
}
```

This code verifies packet bounds and copies the payload bytes. It does not check whether each byte is one of `0x00`, `0x01`, `0x02`, or `0x80`.

### Client subscribe handling consumes the decoded value

File: `wolfMQTT-master/src/mqtt_client.c`

Function: `MqttClient_Subscribe()`

Relevant code:

```c
topic->return_code = subscribe->ack.return_codes[i];
if (topic->return_code & MQTT_SUBSCRIBE_ACK_CODE_FAILURE) {
    any_rejected = 1;
}
```

The client copies the decoded return code into each topic result. For MQTT 3.1.1, a reserved value such as `0x03` has no high bit set, so this logic does not classify it as failure.

## Inconsistency

The standard restricts `SUBACK` return codes to a four-value set. wolfMQTT's receive path treats the return code payload as arbitrary bytes once packet bounds are satisfied.

The missing invariant is:

```text
for each SUBACK return code:
  accept only 0x00, 0x01, 0x02, or 0x80
```

Without that validation, malformed broker responses can enter normal client-side subscription result handling.

## Dynamic Test Evidence

A focused decode test fed valid and reserved `SUBACK` return codes to `MqttDecode_SubscribeAck()`.

Observed output:

```text
valid return code 0x00       rc=5 observed=accept packet_id=1 code0=0x00
valid return code 0x01       rc=5 observed=accept packet_id=1 code0=0x01
valid return code 0x02       rc=5 observed=accept packet_id=1 code0=0x02
valid return code 0x80       rc=5 observed=accept packet_id=1 code0=0x80
reserved return code 0x03    rc=5 observed=accept packet_id=1 code0=0x03
reserved return code 0x7F    rc=5 observed=accept packet_id=1 code0=0x7F
```

The valid values are accepted, which is correct. The reserved values are also accepted, which violates the MQTT 3.1.1 return code requirement.

## Root Cause

The root cause is that `MqttDecode_SubscribeAck()` performs only structural payload parsing. It has no per-return-code membership check after copying the payload bytes.

## Suggested Fix Direction

Validate each decoded return code before accepting the `SUBACK`.

For MQTT 3.1.1, a helper like this would capture the required set:

```c
static int MqttSubAckReturnCode_IsValid(byte code)
{
    return code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS0 ||
           code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS1 ||
           code == MQTT_SUBSCRIBE_ACK_CODE_SUCCESS_MAX_QOS2 ||
           code == MQTT_SUBSCRIBE_ACK_CODE_FAILURE;
}
```

`MqttDecode_SubscribeAck()` should return a malformed-data error if any decoded return code fails this check.
