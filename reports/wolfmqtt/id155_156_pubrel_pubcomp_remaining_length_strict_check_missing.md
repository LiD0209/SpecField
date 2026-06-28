# PUBREL and PUBCOMP Accept Extra Payload in MQTT 3.x

## Summary

wolfMQTT accepts MQTT 3.x `PUBREL` and `PUBCOMP` packets whose Remaining Length is greater than `2`.

In MQTT 3.1.1, `PUBREL` and `PUBCOMP` each contain a two-byte Packet Identifier and no payload. Their Remaining Length is therefore fixed at `2`. A packet such as `62 03 00 07 00` is not a valid MQTT 3.1.1 `PUBREL`, because it carries an extra byte after the Packet Identifier.

The current shared decoder checks only that the Remaining Length is at least two bytes:

```c
if (remain_len < MQTT_DATA_LEN_SIZE) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This accepts malformed MQTT 3.x acknowledgement packets with extra bytes.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant sections:

- `3.6 PUBREL - Publish release`
- `3.6.1 Fixed header`
- `3.6.2 Variable header`
- `3.6.3 Payload`
- `3.7 PUBCOMP - Publish complete`
- `3.7.1 Fixed header`
- `3.7.2 Variable header`
- `3.7.3 Payload`

Short original English excerpt from Section `3.7.1`:

```text
"For the PUBCOMP Packet this has the value 2."
```

Detailed English description of the standard requirement:

For MQTT 3.1.1 `PUBREL`, the fixed header uses packet type `6` and the required fixed-header flags `0010`. Its Remaining Length is `2`, because the variable header contains only the Packet Identifier. The payload is absent.

For MQTT 3.1.1 `PUBCOMP`, the fixed header uses packet type `7` with flags `0000`. Its Remaining Length is also `2`, because the only body field is the Packet Identifier. The payload is absent.

Expected MQTT 3.1.1 packet shapes:

| Packet | Fixed header byte | Remaining Length | Variable header | Payload |
|---|---:|---:|---|---|
| `PUBREL` | `0x62` | `2` | Packet Identifier, 2 bytes | Absent |
| `PUBCOMP` | `0x70` | `2` | Packet Identifier, 2 bytes | Absent |

## Expected Behavior

For MQTT 3.1.1:

| Packet bytes | Meaning | Expected result |
|---|---|---|
| `62 02 00 07` | Valid `PUBREL`, Packet Identifier `7` | Accept |
| `62 03 00 07 00` | `PUBREL` with one extra byte | Reject |
| `70 02 00 07` | Valid `PUBCOMP`, Packet Identifier `7` | Accept |
| `70 03 00 07 00` | `PUBCOMP` with one extra byte | Reject |

The strict MQTT 3.x condition is:

```text
remain_len == MQTT_DATA_LEN_SIZE
```

## Code Evidence

### Encoder Produces the Correct MQTT 3.x Length

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_PublishResp()`

The encoder sets the body length to the two-byte Packet Identifier:

```c
remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
```

For `PUBREL`, the encoder also selects the required QoS value for the fixed-header flags:

```c
qos = (type == MQTT_PACKET_TYPE_PUBLISH_REL) ? MQTT_QOS_1 : MQTT_QOS_0;
```

This produces the correct MQTT 3.1.1 outbound shape for `PUBREL` and `PUBCOMP`.

### Decoder Accepts Any Length of at Least Two Bytes

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_PublishResp()`

The decoder checks only for a minimum body length:

```c
if (remain_len < MQTT_DATA_LEN_SIZE) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

It decodes the Packet Identifier and returns `header_len + remain_len`. In MQTT 3.x builds there is no check that the packet body contains exactly two bytes.

### Broker QoS2 Handlers Use the Shared Decoder

File: `wolfMQTT-master/src/mqtt_broker.c`

`BrokerHandle_PublishRel()` decodes inbound `PUBREL` with the shared decoder:

```c
rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
        MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
```

`BrokerHandle_PublishRec()` uses the same decoder for `PUBREC` and then sends `PUBREL`, showing that this decoder is part of the broker QoS2 acknowledgement flow:

```c
rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
        MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
```

The client receive path also routes `PUBCOMP` through `MqttDecode_PublishResp()` in `wolfMQTT-master/src/mqtt_client.c`.

## Reproduction Test

Test file:

```text
wolfMQTT-master/tests/repro_ack_remaining_length_extra_payload.c
```

Build and run:

```powershell
cd wolfMQTT-master
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c src/mqtt_socket.c src/mqtt_client.c tests/repro_ack_remaining_length_extra_payload.c -o tests/repro_ack_remaining_length_extra_payload.exe
.\tests\repro_ack_remaining_length_extra_payload.exe
```

Relevant observed output:

```text
valid PUBREL length 2              rc=4 packet_id=7 expected=accept observed=accept
extra PUBREL length 3              rc=5 packet_id=7 expected=reject observed=accept
valid PUBCOMP length 2             rc=4 packet_id=7 expected=accept observed=accept
extra PUBCOMP length 3             rc=5 packet_id=7 expected=reject observed=accept
```

The malformed `PUBREL` and `PUBCOMP` packets with Remaining Length `3` were accepted.

## Inconsistency

| Standard requirement | wolfMQTT behavior |
|---|---|
| MQTT 3.1.1 `PUBREL` Remaining Length is fixed at `2` | `PUBREL` with Remaining Length `3` is accepted |
| MQTT 3.1.1 `PUBCOMP` Remaining Length is fixed at `2` | `PUBCOMP` with Remaining Length `3` is accepted |
| These packets have no payload | Extra bytes after the Packet Identifier are not rejected |
| Receive validation should enforce the fixed MQTT 3.x packet body length | Decoder enforces only a minimum length |

## Root Cause

`MqttDecode_PublishResp()` is shared by MQTT 3.x and MQTT 5 publish-response packet handling. MQTT 5 can have reason codes and properties on these packet types, but MQTT 3.1.1 cannot. The current decoder does not add a strict MQTT 3.x branch before accepting `remain_len > 2`.

This conflates:

```text
Packet Identifier is present
```

with:

```text
The MQTT 3.x packet body is exactly the Packet Identifier
```

Only the second condition satisfies MQTT 3.1.1.

## Suggested Fix Direction

Add a protocol-level exact length check for MQTT 3.x in `MqttDecode_PublishResp()`:

```c
#ifdef WOLFMQTT_V5
if (publish_resp == NULL ||
    publish_resp->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5)
#endif
{
    if (remain_len != MQTT_DATA_LEN_SIZE) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
    }
}
```

The broker/client caller should then treat this decode failure as a malformed packet instead of continuing the QoS acknowledgement flow.

