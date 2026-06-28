# Will Topic U+0000 Rejection Is Missing

## Summary

wolfMQTT accepts a malformed MQTT 3.1.1 `CONNECT` packet whose `Will Topic` field contains the forbidden null character `U+0000`.

MQTT 3.1.1 requires UTF-8 encoded strings to exclude `U+0000`, and `Will Topic` is one of the fields that must follow that rule. wolfMQTT's CONNECT decoder parses `Will Topic` with the generic string-length decoder and checks only structural bounds. It does not reject embedded `U+0000`. As a result, a `Will Topic` such as `a\0b` can pass through decoding, and the broker can still return a successful `CONNACK`.

## Standard Reference

MQTT Version 3.1.1, Section `1.5.3 UTF-8 encoded strings`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `1.5.3`.

Original English prohibition:

```text
A UTF-8 encoded string MUST NOT include an encoding of the null character
U+0000.
```

Original English receive-side consequence:

```text
If a receiver (Server or Client) receives a Control Packet containing U+0000 it
MUST close the Network Connection [MQTT-1.5.3-2].
```

MQTT Version 3.1.1, Section `3.1.3 Payload`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.3`.

Original English field requirement:

```text
The Will Topic MUST be a UTF-8 encoded string as defined in Section 1.5.3
[MQTT-3.1.3-10].
```

Together, these rules mean:

```text
Will Topic must satisfy MQTT UTF-8 rules
Will Topic must not contain U+0000
If U+0000 appears, the receiver must not accept the packet
```

## Expected Behavior

For MQTT 3.1.1 CONNECT decoding:

| Will Topic bytes               | Meaning                 | Expected result                                  |
| ------------------------------ | ----------------------- | ------------------------------------------------ |
| valid UTF-8 without `U+0000` | legal Will Topic        | Continue normal CONNECT validation               |
| contains `U+0000`            | forbidden UTF-8 content | Close the network connection / reject the packet |

It is not enough to decode the string length correctly. The decoded character data must also reject the null character.

## Code Description

### Generic string decoder validates only length and bounds

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
```

This function checks only:

- that the two-byte length field is present
- that the declared string length fits within the packet buffer

It does not scan the decoded bytes for:

- `U+0000`
- ill-formed UTF-8
- other MQTT UTF-8 semantic restrictions

### CONNECT decoder uses the generic decoder for Will Topic

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Connect()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &mc_connect->lwt_msg->topic_name,
        &mc_connect->lwt_msg->topic_name_len,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
if (tmp < 0) {
    return tmp;
}
if ((rx_payload - rx_buf) + tmp > header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
rx_payload += tmp;
```

The CONNECT decode path correctly ensures that the `Will Topic` field fits within the packet.

But it does not perform a `Will Topic`-specific check such as:

```c
reject if decoded bytes include U+0000
```

So a length-valid `Will Topic` containing an embedded null can be accepted.

### Broker uses the shared CONNECT decoder and proceeds to normal acceptance

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
```

If decode succeeds, the broker continues into normal CONNECT handling and can return a successful `CONNACK`. There is no later `Will Topic` null-character rejection before acceptance.

## Runtime Reproduction

A broker-level reproducer is available at:

```text
wolfMQTT/301-350/repro_connect_will_topic_u0000.c
```

The reproducer first uses `MqttEncode_Connect()` to build a legal MQTT 3.1.1 CONNECT packet with:

| Field          | Value                                           |
| -------------- | ----------------------------------------------- |
| Protocol Name  | `MQTT`                                        |
| Protocol Level | `4`                                           |
| Connect Flags  | `0x06` (`Clean Session=1`, `Will Flag=1`) |
| ClientId       | `cid`                                         |
| Will Topic     | `abc`                                         |
| Will Message   | `m`                                           |

It then mutates the Will Topic bytes so that the packet contains:

```text
a 00 b
```

The resulting `Will Topic` still has a valid MQTT length prefix, but it contains the forbidden null character `U+0000`.

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\301-350\repro_connect_will_topic_u0000.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\301-350\repro_connect_will_topic_u0000.exe
wolfMQTT\301-350\repro_connect_will_topic_u0000.exe
```

Observed output:

```text
valid packet len=25
u0000 packet len=25
valid will topic decode rc=25 accepted=yes enable_lwt=1 topic_len=3
will topic contains U+0000 decode rc=25 accepted=yes enable_lwt=1 topic_len=3
valid will topic broker connack=20 02 00 00 return_code=0 accepted=yes
will topic contains U+0000 broker connack=20 02 00 00 return_code=0 accepted=yes
```

Interpretation:

- `MqttDecode_Connect()` accepts the `Will Topic` containing `U+0000`.
- The broker returns `20 02 00 00`, which is a successful MQTT 3.1.1 `CONNACK`.
- Therefore `U+0000` in `Will Topic` is not rejected on the receive path.

## Inconsistency

| Standard requirement                                      | wolfMQTT behavior                                     |
| --------------------------------------------------------- | ----------------------------------------------------- |
| A UTF-8 encoded string must not include `U+0000`        | `Will Topic` containing `U+0000` is accepted      |
| Receiver must close the connection on `U+0000`          | Broker returns successful `CONNACK`                 |
| `Will Topic` must satisfy Section `1.5.3` UTF-8 rules | `Will Topic` is decoded with length-only validation |
| Field validation must reject forbidden characters         | Decoder checks only structural bounds                 |

## Inconsistency Reason

The implementation validates only the structural envelope of the `Will Topic` field:

```text
two-byte length exists
declared length fits within the packet
bytes are exposed as the topic field
```

The standard requires semantic character validation as well:

```text
the bytes must not encode U+0000
if U+0000 is present, the packet must not be accepted
```

Because `MqttDecode_String()` is a generic length decoder and `MqttDecode_Connect()` does not add `Will Topic`-specific `U+0000` rejection, the forbidden null character can pass through to the broker.

## Impact

This is a receive-side protocol validation issue with downstream C-string risk.

Potential impact:

| Effect                       | Description                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| Protocol non-compliance      | A malformed MQTT 3.1.1 `CONNECT` packet is accepted instead of causing connection close.              |
| String-consistency break     | `Will Topic` bytes can contain embedded `\0` even though later code may rely on C-string semantics. |
| Logging / matching confusion | Embedded NUL can make one layer see `a\0b` while another effectively sees only `a`.                 |
| Interoperability risk        | Strict MQTT implementations can reject packets that wolfMQTT accepts.                                   |
| Fuzzing blind spot           | Length-valid but semantically forbidden UTF-8 survives the parse boundary.                              |

## Suggested Fix Direction

After decoding the `Will Topic` bytes, the receive path should validate that the field contains no `U+0000` before accepting the packet.

Conceptually:

```c
tmp = MqttDecode_String(...);
if (tmp < 0) {
    return tmp;
}
if (MqttUtf8_ContainsNull(mc_connect->lwt_msg->topic_name,
        mc_connect->lwt_msg->topic_name_len)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The same check should be shared across all MQTT UTF-8 string fields, not only `Will Topic`.
