# Will Flag 0 Extra Will Payload Is Accepted

## Summary

wolfMQTT's CONNECT decoder can accept a malformed MQTT 3.1.1 packet where `Will Flag` is `0`, but the CONNECT payload still contains extra `Will Topic` and `Will Message` fields after the ClientId.

The decoder conditionally parses the Will fields only when `Will Flag` is set. However, after skipping the Will branch, it does not verify that the whole CONNECT payload has been consumed. As a result, trailing will-like fields can be silently ignored, and the broker can still return a successful `CONNACK`.

## Standard Reference

MQTT Version 3.1.1, Section `3.1.2.6 Will Flag`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.2.6`.

Original English requirement:

```text
If the Will Flag is set to 0 the Will QoS and Will Retain fields in the
Connect Flags MUST be set to zero and the Will Topic and Will Message fields
MUST NOT be present in the payload [MQTT-3.1.2-11].
```

MQTT Version 3.1.1, Section `3.1.3 Payload`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.3`.

Original English description:

```text
The Payload of the CONNECT Packet contains one or more length-prefixed fields,
whose presence is determined by the flags in the variable header.
```

The CONNECT payload order is defined as:

```text
Client Identifier
Will Topic
Will Message
User Name
Password
```

Together, these rules mean that `Will Topic` and `Will Message` are allowed only when `Will Flag=1`. If `Will Flag=0`, those fields must not appear in the CONNECT payload.

## Expected Behavior

For MQTT 3.1.1 CONNECT packets:

| Will Flag | Payload after ClientId            | Expected result                 |
| --------: | --------------------------------- | ------------------------------- |
|     `0` | no Will Topic / no Will Message   | Accept this part of the payload |
|     `1` | valid Will Topic + Will Message   | Accept this part of the payload |
|     `0` | Will Topic present                | Reject as malformed             |
|     `0` | Will Message present              | Reject as malformed             |
|     `0` | Will Topic + Will Message present | Reject as malformed             |

The receiver should also verify that after parsing the fields allowed by the flags, no unexpected payload bytes remain.

## Code Description

### Encoder sets Will Flag only when LWT is enabled

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

The encoder constructs normal outbound packets consistently: when LWT is enabled, it sets `Will Flag`; otherwise it does not.

It also writes the Will fields only when `enable_lwt` is present:

```c
if (mc_connect->enable_lwt) {
    tx_payload += MqttEncode_String(tx_payload,
        mc_connect->lwt_msg->topic_name);
    tx_payload += MqttEncode_Data(tx_payload,
        mc_connect->lwt_msg->buffer, (word16)mc_connect->lwt_msg->total_len);
}
```

So wolfMQTT's own construction path normally avoids creating `Will Flag=0` with extra Will payload fields.

### Decoder parses Will fields only when the flag is set

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Connect()`

Relevant code:

```c
mc_connect->enable_lwt =
    (packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) ? 1 : 0;
```

Then the Will Topic and Will Message are decoded only under the conditional branch:

```c
if (mc_connect->enable_lwt) {
    ...
    tmp = MqttDecode_String(rx_payload, &mc_connect->lwt_msg->topic_name,
            &mc_connect->lwt_msg->topic_name_len,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
    ...
    mc_connect->lwt_msg->buffer = rx_payload;
    mc_connect->lwt_msg->buffer_len = mc_connect->lwt_msg->total_len;
    ...
}
```

This branch is correct as far as conditional parsing goes: when `Will Flag=1`, it attempts to read the Will fields.

The missing piece is the corresponding rejection when `Will Flag=0` but extra Will fields remain in the payload.

### Decoder does not check that the payload was fully consumed

At the end of `MqttDecode_Connect()`, the code returns success without verifying that `rx_payload` reached the end of the CONNECT packet:

```c
(void)rx_payload;

/* Return total length of packet */
return header_len + remain_len;
```

There is no check equivalent to:

```c
if ((rx_payload - rx_buf) != header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

Because of this, unexpected trailing bytes can remain after the fields selected by the CONNECT flags have been parsed.

### Broker uses the shared CONNECT decoder

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
```

If decode succeeds, the broker continues normal CONNECT handling and can return a successful `CONNACK`.

## Runtime Reproduction

A broker-level reproducer is available at:

```text
wolfMQTT/301-350/repro_will_flag0_extra_will_payload.c
```

The malformed CONNECT packet uses:

| Field               | Value                                                                                    |
| ------------------- | ---------------------------------------------------------------------------------------- |
| Protocol Name       | `MQTT`                                                                                 |
| Protocol Level      | `4`                                                                                    |
| Connect Flags       | `0x02`                                                                                 |
| Meaning of `0x02` | `Clean Session=1`, `Will Flag=0`                                                     |
| Payload             | ClientId `cid`, then extra Will Topic `will/topic`, then extra Will Message `boom` |

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\301-350\repro_will_flag0_extra_will_payload.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\301-350\repro_will_flag0_extra_will_payload.exe
wolfMQTT\301-350\repro_will_flag0_extra_will_payload.exe
```

Observed output:

```text
valid no will decode rc=17 accepted=yes enable_lwt=0 client_id_len=3 will_topic_present=no will_len=0
will flag 0 with extra will topic/message decode rc=35 accepted=yes enable_lwt=0 client_id_len=3 will_topic_present=no will_len=0
valid no will broker connack=20 02 00 00 return_code=0 accepted=yes
will flag 0 with extra will topic/message broker connack=20 02 00 00 return_code=0 accepted=yes
```

`20 02 00 00` is a successful MQTT 3.1.1 `CONNACK`. The broker accepted the malformed CONNECT packet even though `Will Flag=0` and the payload contained extra `Will Topic` and `Will Message` fields.

## Inconsistency Reason

The implementation follows the flags for conditional field parsing:

```text
if Will Flag is set:
  read Will Topic
  read Will Message
else:
  do not read Will Topic
  do not read Will Message
```

But the standard also requires the inverse consistency rule:

```text
if Will Flag is not set:
  Will Topic must not be present in the payload
  Will Message must not be present in the payload
```

That inverse rule requires either:

- rejecting unexpected trailing payload bytes after the last allowed field; or
- explicitly validating that the payload fields exactly match the CONNECT flags.

wolfMQTT does neither. It returns the total packet length even when `rx_payload` has not consumed all bytes described by the Remaining Length. This lets flag/payload mismatches pass as successful CONNECT packets.

## Impact

This is a protocol input-validation issue on the receive side.

Potential impact:

| Effect                  | Description                                                                                      |
| ----------------------- | ------------------------------------------------------------------------------------------------ |
| Protocol non-compliance | A malformed CONNECT packet is accepted instead of rejected.                                      |
| Parser ambiguity        | The packet contains bytes that look like Will fields, but the flag says no Will exists.          |
| Broker acceptance gap   | The stock broker can return successful `CONNACK` for a malformed CONNECT packet.               |
| Interoperability risk   | Strict MQTT peers can reject packets that wolfMQTT accepts.                                      |
| Fuzzing blind spot      | Extra payload bytes can be hidden behind an unset Will Flag without surfacing as malformed data. |

## Suggested Fix Direction

After all flag-selected CONNECT payload fields are parsed, `MqttDecode_Connect()` should verify full payload consumption:

```c
if ((rx_payload - rx_buf) != header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would reject:

| CONNECT condition                                                  | Expected rejection reason                         |
| ------------------------------------------------------------------ | ------------------------------------------------- |
| `Will Flag=0`, trailing Will Topic field present                 | unexpected payload bytes                          |
| `Will Flag=0`, trailing Will Message field present               | unexpected payload bytes                          |
| `Will Flag=0`, trailing Will Topic + Will Message fields present | unexpected payload bytes                          |
| Any extra bytes after the last valid CONNECT payload field         | payload does not match Remaining Length semantics |

The same validation area should also be combined with explicit CONNECT flag cross-checks such as:

- reject `Will QoS != 0` when `Will Flag=0`
- reject `Will Retain = 1` when `Will Flag=0`
