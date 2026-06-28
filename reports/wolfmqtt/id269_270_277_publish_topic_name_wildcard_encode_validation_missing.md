# PUBLISH Topic Name Wildcard Validation Is Missing on Encode Path

## Summary

wolfMQTT's broker receive path rejects inbound `PUBLISH` packets whose Topic Name contains wildcard characters `+` or `#`, but the generic `MqttEncode_Publish()` API can still construct such packets.

This creates an inconsistent implementation boundary:

```text
broker inbound PUBLISH path: rejects Topic Name containing + or #
generic PUBLISH encode path: accepts and serializes Topic Name containing + or #
```

MQTT 3.1.1 forbids wildcard characters in Topic Names. Wildcards are valid only in Topic Filters used for subscriptions.

## Standard Reference

MQTT Version 3.1.1, Section `4.7.1 Topic wildcards`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `4.7.1`.

Original English requirement:

```text
The wildcard characters can be used in Topic Filters, but MUST NOT be used within a Topic Name [MQTT-4.7.1-1].
```

MQTT Version 3.1.1, Section `3.3.2.1 Topic Name`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.3.2.1`.

Original English requirement:

```text
The Topic Name in the PUBLISH Packet MUST NOT contain wildcard characters [MQTT-3.3.2-2].
```

Original English description:

```text
The Topic Name identifies the information channel to which payload data is published.
```

These requirements mean that a `PUBLISH` Topic Name such as `sensor/#` or `sensor/+` is invalid. Those strings may be subscription Topic Filters, but they must not appear as PUBLISH Topic Names.

## Expected Behavior

For PUBLISH construction and receive paths:

| Topic Name       | Expected result |
| ---------------- | --------------- |
| `sensor/value` | Accept          |
| `sensor/#`     | Reject          |
| `sensor/+`     | Reject          |
| `+`            | Reject          |
| `#`            | Reject          |

The same Topic Name validity rule should be enforced consistently wherever wolfMQTT creates or accepts PUBLISH packets.

## Code Description

### Broker receive path rejects wildcard Topic Names

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

The built-in broker therefore has an inbound protection for network-originated PUBLISH packets. A remote publisher using `sensor/#` or `sensor/+` as a Topic Name is rejected by this broker path.

### Generic PUBLISH encoder does not enforce the same rule

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_Publish()`

Relevant code:

```c
variable_len = (int)XSTRLEN(publish->topic_name) + MQTT_DATA_LEN_SIZE;
```

```c
tx_payload += MqttEncode_String(tx_payload, publish->topic_name);
```

The encoder computes the Topic Name length with `XSTRLEN()` and serializes the string. It does not scan the Topic Name for `+` or `#`, and it does not return an error when those wildcard characters are present.

### Generic PUBLISH decoder also accepts wildcard Topic Names structurally

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

The decoder reads a length-prefixed Topic Name and returns it to the caller. The broker adds a later wildcard check, but the packet-level decoder itself does not enforce the Topic Name wildcard rule.

## Runtime Reproduction

### Encoder accepts wildcard Topic Names

A focused encoder/decoder reproducer is available at:

`wolfMQTT/251-300/repro_publish_topic_name_wildcard_encode.c`

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ wolfMQTT\251-300\repro_publish_topic_name_wildcard_encode.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_socket.c wolfMQTT-master\src\mqtt_client.c -o wolfMQTT\251-300\repro_publish_topic_name_wildcard_encode.exe
wolfMQTT\251-300\repro_publish_topic_name_wildcard_encode.exe
```

Observed output:

```text
valid topic encode rc=17 bytes=30 0F 00 0C 73 65 6E 73 6F 72 2F 76 61 6C 75 65 78
valid topic decode rc=17 topic_len=12 topic=sensor/value
invalid multi wildcard topic encode rc=13 bytes=30 0B 00 08 73 65 6E 73 6F 72 2F 23 78
invalid multi wildcard topic decode rc=13 topic_len=8 topic=sensor/#
invalid single wildcard topic encode rc=13 bytes=30 0B 00 08 73 65 6E 73 6F 72 2F 2B 78
invalid single wildcard topic decode rc=13 topic_len=8 topic=sensor/+
```

The encoder successfully serializes two invalid PUBLISH Topic Names:

| Topic Name   | Encoded result |
| ------------ | -------------- |
| `sensor/#` | Accepted       |
| `sensor/+` | Accepted       |

The packet decoder then decodes those invalid Topic Names successfully as ordinary strings.

### Broker receive path rejects the same wildcard Topic Name

A broker-level comparison reproducer is available at:

`wolfMQTT/251-300/repro_broker_rejects_publish_topic_wildcards.c`

The reproducer sends a valid `CONNECT`, then sends a QoS 1 `PUBLISH` whose Topic Name is `sensor/#`.

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\251-300\repro_broker_rejects_publish_topic_wildcards.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\251-300\repro_broker_rejects_publish_topic_wildcards.exe
wolfMQTT\251-300\repro_broker_rejects_publish_topic_wildcards.exe
```

Observed output:

```text
MqttBroker_Start rc=0
accept/connect step rc=0 output_len=4
broker: PUBLISH topic contains wildcard sock=101
wildcard publish step rc=0 output_len=4
broker output: 20 02 00 00
```

The broker output contains only the successful `CONNACK`:

```text
20 02 00 00
```

It does not contain a `PUBACK` for the QoS 1 `PUBLISH`, which confirms that the broker receive path rejects the wildcard Topic Name.

## Inconsistency Reason

The inconsistency is caused by validation being placed only in the broker receive path.

The current implementation behaves like this:

```text
MqttEncode_Publish()
  accepts Topic Name containing + or #
  serializes malformed PUBLISH packet

MqttDecode_Publish()
  accepts Topic Name containing + or #
  exposes it to caller

BrokerHandle_Publish()
  adds broker-specific rejection for + or #
```

This means the built-in broker has partial protection, but the library-level PUBLISH construction path does not provide the same MQTT invariant.

The standard rule applies to Topic Names, not only to broker-received Topic Names. A generic API that constructs MQTT PUBLISH packets should not allow callers to produce packets that MQTT forbids.

## Impact

This is a protocol compliance and interoperability issue.

Potential impact:

| Effect                      | Description                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Invalid packet construction | Applications using `MqttEncode_Publish()` can generate PUBLISH packets with forbidden Topic Names.                      |
| Inconsistent behavior       | wolfMQTT may reject the same malformed Topic Name when received by the broker but allow it when generated by the encoder. |
| Interoperability risk       | Strict MQTT brokers can reject packets produced by a wolfMQTT-based sender.                                               |
| Validation gap              | Applications must duplicate Topic Name validation themselves to avoid emitting invalid MQTT traffic.                      |

## Suggested Fix Direction

Add a Topic Name validation helper shared by encode and decode callers:

```c
static int MqttValidate_TopicName(const char* topic_name, word16 topic_len)
{
    if (topic_len == 0) {
        return MQTT_CODE_ERROR_MALFORMED_DATA;
    }
    for (i = 0; i < topic_len; i++) {
        if (topic_name[i] == '+' || topic_name[i] == '#') {
            return MQTT_CODE_ERROR_MALFORMED_DATA;
        }
    }
    return MQTT_CODE_SUCCESS;
}
```

`MqttEncode_Publish()` should reject Topic Names containing `+` or `#` before serializing the packet.

The same validation should be applied consistently after `MqttDecode_Publish()` reads the Topic Name, either inside the decoder or through a mandatory caller-side validation path.

If empty Topic Name validation is handled in a separate helper, the wildcard check still needs to be shared by both the generic PUBLISH encoder and the receive-side PUBLISH validation path.
