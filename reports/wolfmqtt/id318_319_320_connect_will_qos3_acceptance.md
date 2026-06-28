# Reserved Will QoS Value 3 Is Accepted

## Summary

wolfMQTT's CONNECT decoder accepts a malformed MQTT 3.1.1 packet where `Will Flag` is `1`, but the two-bit `Will QoS` field is set to the reserved value `3`.

In MQTT 3.1.1, `Will QoS` is valid only when `Will Flag=1`, and even then the only legal values are `0`, `1`, and `2`. The value `3` is explicitly forbidden. wolfMQTT currently extracts the two-bit value directly from the CONNECT flags and stores it into the decoded LWT state without rejecting the reserved value. The stock broker then accepts the CONNECT packet and returns a successful `CONNACK`.

## Standard Reference

MQTT Version 3.1.1, Section `3.1.2.6 Will Flag` and Section `3.1.2.7 Will QoS`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Sections `3.1.2.6` and `3.1.2.7`.

Original English requirement:

```text
If the Will Flag is set to 1, the value of Will QoS can be 0 (0x00), 1
(0x01), or 2 (0x02). It MUST NOT be 3 (0x03) [MQTT-3.1.2-14].
```

Related English description from Section `3.1.2.6`:

```text
If the Will Flag is set to 1, the Will QoS and Will Retain fields in the
Connect Flags will be used by the Server, and the Will Topic and Will Message
fields MUST be present in the payload.
```

These rules mean that when `Will Flag=1`, the receiver must not merely extract the two-bit value. It must also enforce the legal set:

```text
Will QoS in {0, 1, 2}
Will QoS != 3
```

## Expected Behavior

For MQTT 3.1.1 CONNECT decoding:

| Will Flag | Will QoS bits | Meaning              | Expected result     |
| --------: | ------------: | -------------------- | ------------------- |
|     `1` |        `00` | QoS 0                | Accept              |
|     `1` |        `01` | QoS 1                | Accept              |
|     `1` |        `10` | QoS 2                | Accept              |
|     `1` |        `11` | Reserved value `3` | Reject as malformed |

The important rule is not just that `Will QoS` is present when `Will Flag=1`, but that its value is restricted to the legal set `{0,1,2}`.

## Code Description

### Encoder constructs normal values from caller-provided LWT state

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_Connect()`

Relevant code:

```c
if (mc_connect->enable_lwt) {
    packet.flags |= MQTT_CONNECT_FLAG_WILL_FLAG;

    if (mc_connect->lwt_msg->qos) {
        packet.flags |= MQTT_CONNECT_FLAG_SET_QOS(mc_connect->lwt_msg->qos);
    }
    if (mc_connect->lwt_msg->retain) {
        packet.flags |= MQTT_CONNECT_FLAG_WILL_RETAIN;
    }
}
```

The normal outbound path derives the CONNECT flags from the configured LWT state. This path does not itself prove that `qos=3` is impossible from all callers, but its main role here is that the decoder cannot rely on construction-time discipline when parsing network input.

### Decoder extracts Will QoS directly and does not reject value 3

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Connect()`

Relevant code:

```c
mc_connect->enable_lwt =
    (packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) ? 1 : 0;
```

When `Will Flag=1`, the decoder enters the LWT branch and directly assigns the two-bit Will QoS value:

```c
mc_connect->lwt_msg->qos =
    (MqttQoS)MQTT_CONNECT_FLAG_GET_QOS(packet.flags);
mc_connect->lwt_msg->retain =
    (packet.flags & MQTT_CONNECT_FLAG_WILL_RETAIN) ? 1 : 0;
```

There is no validation equivalent to:

```c
if (MQTT_CONNECT_FLAG_GET_QOS(packet.flags) == 3) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

So a CONNECT packet with `Will Flag=1` and `Will QoS=3` is decoded as if `qos=3` were a legitimate application value.

### Broker stores the decoded reserved Will QoS value

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
bc->will_qos = mc.lwt_msg->qos;
bc->will_retain = mc.lwt_msg->retain;
```

The broker does not reject a reserved `Will QoS` before storing it into the connection state. As a result, the malformed CONNECT can continue through the normal accepted-connection path.

## Runtime Reproduction

A broker-level reproducer is available at:

```text
wolfMQTT/301-350/repro_connect_will_qos_flag_validation.c
```

The malformed CONNECT packet uses:

| Field               | Value                                                                   |
| ------------------- | ----------------------------------------------------------------------- |
| Protocol Name       | `MQTT`                                                                |
| Protocol Level      | `4`                                                                   |
| Connect Flags       | `0x1E`                                                                |
| Meaning of `0x1E` | `Clean Session=1`, `Will Flag=1`, `Will QoS=3`, `Will Retain=0` |
| Payload             | ClientId `cid`, Will Topic `t`, Will Message `m`                  |

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\301-350\repro_connect_will_qos_flag_validation.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\301-350\repro_connect_will_qos_flag_validation.exe
wolfMQTT\301-350\repro_connect_will_qos_flag_validation.exe
```

Relevant observed output:

```text
will flag 1 but qos=3 decode rc=23 accepted=yes enable_lwt=1 will_qos=3 will_retain=0
will flag 1 but qos=3 broker connack=20 02 00 00 return_code=0 accepted=yes
```

Interpretation:

- `MqttDecode_Connect()` accepts the malformed CONNECT and decodes `will_qos=3`.
- The broker returns `20 02 00 00`, which is a successful MQTT 3.1.1 `CONNACK`.
- Therefore the reserved `Will QoS` value is not rejected on the receive path.

## Inconsistency

| Standard requirement                                                | wolfMQTT behavior                                              |
| ------------------------------------------------------------------- | -------------------------------------------------------------- |
| If `Will Flag=1`, `Will QoS` may be only `0`, `1`, or `2` | `Will QoS=3` is decoded and accepted                         |
| `Will QoS=3` MUST NOT be used                                     | Reserved value `3` is stored into LWT state                  |
| Malformed CONNECT flags should be rejected                          | Broker returns successful `CONNACK`                          |
| Protocol-level value validation must constrain the decoded field    | Decoder only extracts bits; it does not validate the legal set |

## Inconsistency Reason

The implementation performs this step:

```text
extract the two-bit Will QoS value from the CONNECT flags
```

But it misses the required second step:

```text
validate that the extracted value is one of {0,1,2}
```

That conflates:

```text
the field is present
```

with:

```text
the field value is legal
```

MQTT 3.1.1 requires both. wolfMQTT currently does only the first one for this case.

## Impact

This is a receive-side protocol validation issue.

Potential impact:

| Effect                    | Description                                                                    |
| ------------------------- | ------------------------------------------------------------------------------ |
| Protocol non-compliance   | A malformed CONNECT packet is accepted instead of rejected.                    |
| Reserved-value acceptance | The implementation stores and propagates a forbidden Will QoS value.           |
| Broker behavior ambiguity | Later Will publication paths may operate on a non-standard QoS state.          |
| Interoperability risk     | Strict MQTT peers can reject packets that wolfMQTT accepts.                    |
| Fuzzing blind spot        | Reserved flag-value combinations can enter the accepted CONNECT state machine. |

## Suggested Fix Direction

`MqttDecode_Connect()` should reject reserved `Will QoS=3` immediately after extracting the CONNECT flags and before decoding the Will payload fields:

```c
if ((packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) &&
    MQTT_CONNECT_FLAG_GET_QOS(packet.flags) == 3) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This should be applied in the same validation area that handles other CONNECT flag cross-constraints, so the receive path rejects invalid flag combinations before they can enter normal broker processing.
