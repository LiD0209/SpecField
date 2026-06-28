# PUBACK and PUBREC Accept Extra Payload in MQTT 3.x

## Summary

wolfMQTT accepts MQTT 3.x `PUBACK` and `PUBREC` packets whose Remaining Length is greater than `2`.

In MQTT 3.1.1, `PUBACK` and `PUBREC` each contain exactly one variable-header field: the two-byte Packet Identifier. They have no payload. Therefore their Remaining Length is fixed at `2`. A packet such as `40 03 00 07 00` is not a valid MQTT 3.1.1 `PUBACK`, because it contains an extra byte after the Packet Identifier.

The current shared decoder checks only that the Remaining Length is at least two bytes:

```c
if (remain_len < MQTT_DATA_LEN_SIZE) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This accepts `remain_len = 3`, `4`, or larger in MQTT 3.x, leaving extra bytes unvalidated.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant sections:

- `3.4 PUBACK - Publish acknowledgement`
- `3.4.1 Fixed header`
- `3.4.2 Variable header`
- `3.4.3 Payload`
- `3.5 PUBREC - Publish received`
- `3.5.1 Fixed header`
- `3.5.2 Variable header`
- `3.5.3 Payload`

Short original English excerpt from Section `3.4.1`:

```text
"For the PUBACK Packet this has the value 2."
```

Detailed English description of the standard requirement:

For MQTT 3.1.1 `PUBACK`, the fixed header declares a Remaining Length of `2`. The variable header is exactly the Packet Identifier from the corresponding QoS 1 `PUBLISH`. The payload section states that the packet has no payload. Therefore, after the fixed header, exactly two bytes are valid.

For MQTT 3.1.1 `PUBREC`, the same structure applies: the fixed header Remaining Length is `2`, the variable header is the two-byte Packet Identifier, and there is no payload. `PUBREC` is the response to a QoS 2 `PUBLISH`, but it is still a fixed-size MQTT 3.1.1 acknowledgement packet.

Expected MQTT 3.1.1 packet shapes:

| Packet | Fixed header byte | Remaining Length | Variable header | Payload |
|---|---:|---:|---|---|
| `PUBACK` | `0x40` | `2` | Packet Identifier, 2 bytes | Absent |
| `PUBREC` | `0x50` | `2` | Packet Identifier, 2 bytes | Absent |

## Expected Behavior

For MQTT 3.1.1:

| Packet bytes | Meaning | Expected result |
|---|---|---|
| `40 02 00 07` | Valid `PUBACK`, Packet Identifier `7` | Accept |
| `40 03 00 07 00` | `PUBACK` with one extra byte | Reject |
| `50 02 00 07` | Valid `PUBREC`, Packet Identifier `7` | Accept |
| `50 03 00 07 00` | `PUBREC` with one extra byte | Reject |

The strict condition for MQTT 3.x is:

```text
remain_len == MQTT_DATA_LEN_SIZE
```

Checking only `remain_len >= MQTT_DATA_LEN_SIZE` is too permissive.

## Code Evidence

### Encoder Produces the Correct MQTT 3.x Length

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_PublishResp()`

The encoder starts with a Remaining Length of two bytes for the Packet Identifier:

```c
remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
```

For MQTT 3.x builds, no reason code or properties are added. This means the outbound `PUBACK` and `PUBREC` encoding path produces a Remaining Length of `2`, which matches MQTT 3.1.1.

### Decoder Accepts Any Length of at Least Two Bytes

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_PublishResp()`

The decoder performs only a lower-bound check:

```c
if (remain_len < MQTT_DATA_LEN_SIZE) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

It then decodes only the Packet Identifier:

```c
tmp = MqttDecode_Num(rx_payload, &publish_resp->packet_id,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

For MQTT 3.x, there is no subsequent check that `remain_len` was exactly `2`. Extra bytes after the Packet Identifier are therefore accepted.

### Client Receive Path Uses the Shared Decoder

File: `wolfMQTT-master/src/mqtt_client.c`

The client receive path routes publish acknowledgement packets through `MqttDecode_PublishResp()`:

```c
case MQTT_PACKET_TYPE_PUBLISH_ACK:
case MQTT_PACKET_TYPE_PUBLISH_REC:
case MQTT_PACKET_TYPE_PUBLISH_REL:
case MQTT_PACKET_TYPE_PUBLISH_COMP:
    rc = MqttDecode_PublishResp(rx_buf, rx_len, packet_type,
        p_publish_resp);
```

Therefore, this permissive length check affects client-side handling of inbound `PUBACK` and `PUBREC` packets.

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
valid PUBACK length 2              rc=4 packet_id=7 expected=accept observed=accept
extra PUBACK length 3              rc=5 packet_id=7 expected=reject observed=accept
valid PUBREC length 2              rc=4 packet_id=7 expected=accept observed=accept
extra PUBREC length 3              rc=5 packet_id=7 expected=reject observed=accept
```

The return values `rc=5` show that the malformed packets with an extra byte were decoded successfully.

## Inconsistency

| Standard requirement | wolfMQTT behavior |
|---|---|
| MQTT 3.1.1 `PUBACK` Remaining Length is fixed at `2` | `PUBACK` with Remaining Length `3` is accepted |
| MQTT 3.1.1 `PUBREC` Remaining Length is fixed at `2` | `PUBREC` with Remaining Length `3` is accepted |
| These packets have no payload | Extra bytes after the Packet Identifier are not rejected |
| Receive validation should enforce the MQTT 3.x packet shape | Decoder enforces only a lower bound |

## Root Cause

The shared publish-response decoder treats the two-byte Packet Identifier as a minimum required field, but for MQTT 3.x it is the complete packet body.

The decoder currently answers this question:

```text
Does the packet contain enough bytes to decode a Packet Identifier?
```

MQTT 3.1.1 requires a stricter question:

```text
Does the packet contain exactly the Packet Identifier and no payload?
```

## Suggested Fix Direction

For MQTT 3.x, add an exact Remaining Length check in `MqttDecode_PublishResp()`:

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

The MQTT 5 path can continue to allow longer forms when reason codes or properties are valid for that protocol level.

