# Empty PUBLISH Topic Names Are Accepted

## Summary

wolfMQTT can encode and decode MQTT `PUBLISH` packets with an empty Topic Name.

The built-in broker also accepts a QoS 1 `PUBLISH` whose Topic Name length is `0x0000` and replies with `PUBACK`. This is inconsistent with MQTT 3.1.1 because all Topic Names must contain at least one character.

## Standard Reference

MQTT Version 3.1.1, Section `4.7.3 Topic semantic and usage`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `4.7.3`.

Original English requirement:

```text
All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1].
```

MQTT Version 3.1.1, Section `3.3.2.1 Topic Name`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.3.2.1`.

Original English requirement:

```text
The Topic Name identifies the information channel to which payload data is published.
```

Therefore, a `PUBLISH` packet whose Topic Name field has length zero is malformed.

## Expected Behavior

For MQTT 3.1.1 `PUBLISH` packets:

| Topic Name length | Expected result                                      |
| ----------------: | ---------------------------------------------------- |
|             `0` | Reject as malformed                                  |
|          `>= 1` | Continue normal processing if other fields are valid |

The rule should be enforced consistently on both packet construction and packet receive paths.

## Code Description

### PUBLISH encoder allows empty Topic Name

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_Publish()`

Relevant code:

```c
variable_len = (int)XSTRLEN(publish->topic_name) + MQTT_DATA_LEN_SIZE;
```

```c
tx_payload += MqttEncode_String(tx_payload, publish->topic_name);
```

If `publish->topic_name` is an empty string, `XSTRLEN()` returns `0`. The encoder still adds the two-byte MQTT string length field and serializes a Topic Name with length `0x0000`. There is no check equivalent to:

```c
if (XSTRLEN(publish->topic_name) == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

### PUBLISH decoder accepts zero-length Topic Name

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Publish()`

Relevant code:

```c
variable_len = MqttDecode_String(rx_payload, &publish->topic_name,
    &publish->topic_name_len, (word32)(rx_buf_len - (rx_payload - rx_buf)));
if ((variable_len >= 0) && (variable_len + header_len <= rx_buf_len)) {
    rx_payload += variable_len;
}
else {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
```

`MqttDecode_String()` validates the two-byte string length and packet bounds, but it permits `str_len == 0`. After decoding, `MqttDecode_Publish()` does not reject `publish->topic_name_len == 0`.

### Broker receive path does not reject empty Topic Name

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Publish()`

Relevant code:

```c
/* [MQTT-3.3.2-2] PUBLISH topic must not contain wildcard characters */
if (pub.topic_name && pub.topic_name_len > 0) {
    word16 i;
    for (i = 0; i < pub.topic_name_len; i++) {
        if (pub.topic_name[i] == '+' || pub.topic_name[i] == '#') {
            WBLOG_ERR(broker,
                "broker: PUBLISH topic contains wildcard sock=%d",
                (int)bc->sock);
            return MQTT_CODE_ERROR_BAD_ARG;
        }
    }
}
```

This branch checks for wildcard characters only when `pub.topic_name_len > 0`. If the Topic Name length is zero, the branch is skipped.

The broker later creates a null-terminated topic copy only when the length is non-zero:

```c
if (pub.topic_name && pub.topic_name_len > 0) {
    ...
    topic = topic_buf;
}
```

For a QoS 1 empty-topic `PUBLISH`, the broker still reaches the acknowledgement path and sends `PUBACK`.

## Runtime Reproduction

A focused reproducer is available at:

`wolfMQTT/251-300/repro_publish_empty_topic_name.c`

The reproducer checks three paths:

| Path           | Test                                                |
| -------------- | --------------------------------------------------- |
| Encode         | `MqttEncode_Publish()` with `topic_name=""`     |
| Decode         | `MqttDecode_Publish()` on the encoded packet      |
| Broker receive | QoS 1 `PUBLISH` with Topic Name length `0x0000` |

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\251-300\repro_publish_empty_topic_name.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\251-300\repro_publish_empty_topic_name.exe
wolfMQTT\251-300\repro_publish_empty_topic_name.exe
```

Observed output:

```text
encode empty topic rc=5 bytes=30 03 00 00 78
decode encoded empty topic rc=5 topic_len=0 payload_len=1
MqttBroker_Start rc=0
accept/connect step rc=0 output_len=4
publish step rc=0 output_len=8
broker output: 20 02 00 00 40 02 00 07
```

The encoded packet bytes:

```text
30 03 00 00 78
```

mean:

| Bytes     | Meaning             |
| --------- | ------------------- |
| `30`    | `PUBLISH` QoS 0   |
| `03`    | Remaining Length 3  |
| `00 00` | Topic Name length 0 |
| `78`    | Payload `x`       |

The broker output:

```text
20 02 00 00 40 02 00 07
```

contains:

| Bytes           | Meaning                            |
| --------------- | ---------------------------------- |
| `20 02 00 00` | Successful `CONNACK`             |
| `40 02 00 07` | `PUBACK` for Packet Identifier 7 |

The `PUBACK` confirms that the broker accepted and acknowledged the QoS 1 `PUBLISH` with an empty Topic Name.

## Inconsistency Reason

The implementation treats the Topic Name as a generic MQTT UTF-8 string envelope:

```text
two-byte length exists
declared length fits in packet
bytes are exposed to caller
```

But the MQTT Topic Name rule adds a field-specific semantic constraint:

```text
Topic Name length must be at least one character
```

Because neither `MqttEncode_Publish()` nor `MqttDecode_Publish()` enforces that field-specific rule, empty Topic Names can be constructed and parsed. Because the broker receive path also omits a zero-length rejection, it can acknowledge a malformed QoS 1 `PUBLISH`.

## Impact

This is a protocol input-validation and packet-construction issue.

Potential impact:

| Effect                   | Description                                                                |
| ------------------------ | -------------------------------------------------------------------------- |
| Protocol non-compliance  | wolfMQTT accepts and emits PUBLISH packets that MQTT 3.1.1 forbids.        |
| Routing ambiguity        | An empty Topic Name has no valid MQTT information channel.                 |
| Interoperability risk    | Strict MQTT peers can reject packets generated by wolfMQTT.                |
| Broker behavior mismatch | The broker acknowledges a malformed QoS 1 PUBLISH instead of rejecting it. |

## Suggested Fix Direction

Add a Topic Name validation helper and use it from PUBLISH encode and decode paths:

```c
if (topic_name_len == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The check should be applied:

| Location                   | Required behavior                                                       |
| -------------------------- | ----------------------------------------------------------------------- |
| `MqttEncode_Publish()`   | Reject empty `publish->topic_name` before serialization               |
| `MqttDecode_Publish()`   | Reject `publish->topic_name_len == 0` after string decoding           |
| `BrokerHandle_Publish()` | Treat empty Topic Name as malformed and avoid acknowledging it as valid |
