# Will Topic UTF-8 Validation Is Missing

## Summary

wolfMQTT accepts a malformed MQTT 3.1.1 `CONNECT` packet whose `Will Topic` field contains ill-formed UTF-8.

The CONNECT decoder parses `Will Topic` with the generic string-length decoder and checks only structural bounds. It does not validate the UTF-8 character semantics required by MQTT 3.1.1. As a result, malformed UTF-8 bytes in `Will Topic` can pass through decoding, and the broker can still return a successful `CONNACK`.

## Standard Reference

MQTT Version 3.1.1, Section `1.5.3 UTF-8 encoded strings`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `1.5.3`.

Original English requirement:

```text
The character data in a UTF-8 encoded string MUST be well-formed UTF-8 as
defined by the Unicode specification [Unicode] and restated in RFC 3629
[RFC3629].
```

Original English receive-side consequence:

```text
If a Server or Client receives a Control Packet containing ill-formed UTF-8 it
MUST close the Network Connection [MQTT-1.5.3-1].
```

MQTT Version 3.1.1, Section `3.1.3 Payload`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.3`.

Original English field requirement:

```text
The Will Topic MUST be a UTF-8 encoded string as defined in Section 1.5.3
[MQTT-3.1.3-10].
```

Together, these requirements mean:

```text
Will Topic must be a UTF-8 encoded string
Will Topic character data must be well-formed UTF-8
Ill-formed UTF-8 in Will Topic must not be accepted
```

## Expected Behavior

For MQTT 3.1.1 CONNECT decoding:

| Will Topic bytes | Meaning              | Expected result                                  |
| ---------------- | -------------------- | ------------------------------------------------ |
| valid UTF-8      | legal Will Topic     | Continue normal CONNECT validation               |
| ill-formed UTF-8 | malformed Will Topic | Close the network connection / reject the packet |

Checking only that the string length field fits within the packet is not sufficient. The byte sequence itself must also be valid UTF-8.

## Code Description

### Generic string decoder validates only length and packet bounds

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

This function recovers the declared string length and ensures that the bytes fit inside the packet buffer.

It does not validate:

- UTF-8 well-formedness
- overlong encodings
- surrogate-range encodings
- other semantic UTF-8 constraints from MQTT Section `1.5.3`

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

The CONNECT decode path correctly checks:

- that the Will Topic field exists when the LWT branch is taken
- that the decoded length does not exceed packet bounds

But it does not add any `Will Topic`-specific UTF-8 validation after length decoding.

### Broker uses the shared CONNECT decoder and accepts the malformed field

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
```

If decode succeeds, the broker proceeds into normal CONNECT acceptance and Will storage logic. There is no later `Will Topic` UTF-8 semantic validation before successful `CONNACK`.

## Runtime Reproduction

A broker-level reproducer is available at:

```text
wolfMQTT/301-350/repro_connect_will_topic_invalid_utf8.c
```

The reproducer first uses `MqttEncode_Connect()` to build a legal MQTT 3.1.1 CONNECT packet with:

| Field          | Value                                           |
| -------------- | ----------------------------------------------- |
| Protocol Name  | `MQTT`                                        |
| Protocol Level | `4`                                           |
| Connect Flags  | `0x06` (`Clean Session=1`, `Will Flag=1`) |
| ClientId       | `cid`                                         |
| Will Topic     | `t`                                           |
| Will Message   | `m`                                           |

It then mutates only the Will Topic bytes from:

```text
00 01 74
```

to:

```text
00 02 C0 AF
```

`C0 AF` is an overlong UTF-8 byte sequence and is ill-formed under RFC 3629.

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\301-350\repro_connect_will_topic_invalid_utf8.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\301-350\repro_connect_will_topic_invalid_utf8.exe
wolfMQTT\301-350\repro_connect_will_topic_invalid_utf8.exe
```

Observed output:

```text
valid will topic decode rc=23 accepted=yes enable_lwt=1 topic_len=1
invalid utf8 will topic decode rc=24 accepted=yes enable_lwt=1 topic_len=2
valid will topic broker connack=20 02 00 00 return_code=0 accepted=yes
invalid utf8 will topic broker connack=20 02 00 00 return_code=0 accepted=yes
```

Interpretation:

- `MqttDecode_Connect()` accepts the malformed `Will Topic` field.
- The broker returns `20 02 00 00`, which is a successful MQTT 3.1.1 `CONNACK`.
- Therefore ill-formed UTF-8 in `Will Topic` is not rejected on the receive path.

## Inconsistency

| Standard requirement                                                       | wolfMQTT behavior                                     |
| -------------------------------------------------------------------------- | ----------------------------------------------------- |
| `Will Topic` must be a UTF-8 encoded string defined by Section `1.5.3` | `Will Topic` is decoded with length-only validation |
| UTF-8 character data must be well-formed                                   | Ill-formed byte sequences are accepted                |
| Receiving a Control Packet with ill-formed UTF-8 must close the connection | Broker returns successful `CONNACK`                 |
| Field validation must include semantic UTF-8 checks                        | Decoder validates only the structural envelope        |

## Inconsistency Reason

The implementation validates only the structural envelope of the `Will Topic` field:

```text
two-byte length exists
declared length fits inside the packet
bytes are exposed as a field pointer
```

The standard requires semantic validation of the character data:

```text
the bytes must be well-formed UTF-8
if not, the packet must not be accepted
```

Because `MqttDecode_String()` is a generic length decoder and `MqttDecode_Connect()` does not add `Will Topic`-specific UTF-8 validation, malformed UTF-8 can pass through to the broker.

## Impact

This is a receive-side protocol input-validation issue.

Potential impact:

| Effect                   | Description                                                                                                     |
| ------------------------ | --------------------------------------------------------------------------------------------------------------- |
| Protocol non-compliance  | A malformed MQTT 3.1.1 `CONNECT` packet is accepted instead of causing connection close.                      |
| Invalid UTF-8 acceptance | Will Topic bytes that are not valid UTF-8 can enter broker state.                                               |
| Interoperability risk    | Strict MQTT implementations can reject packets that wolfMQTT accepts.                                           |
| Robustness risk          | Later logic may assume `Will Topic` is valid UTF-8 even though the broker accepted arbitrary malformed bytes. |
| Fuzzing blind spot       | Length-valid but semantically invalid UTF-8 survives the parse boundary.                                        |

## Suggested Fix Direction

After `MqttDecode_String()` returns the Will Topic bytes, the receive path should validate that the byte sequence is a well-formed MQTT UTF-8 encoded string before accepting the packet.

Conceptually:

```c
tmp = MqttDecode_String(...);
if (tmp < 0) {
    return tmp;
}
if (!MqttUtf8_IsValid(mc_connect->lwt_msg->topic_name,
        mc_connect->lwt_msg->topic_name_len)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The same UTF-8 semantic validation should be shared across all MQTT UTF-8 string fields, including:

- `ClientId`
- `Will Topic`
- `Topic Name`
- `Topic Filter`
- `User Name`
