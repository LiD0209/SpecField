# Empty SUBSCRIBE and UNSUBSCRIBE Payloads Are Accepted

## Summary

wolfMQTT accepts malformed MQTT 3.1.1 `SUBSCRIBE` and `UNSUBSCRIBE` packets whose payload is empty.

In MQTT 3.1.1, a `SUBSCRIBE` payload must contain at least one `Topic Filter / QoS` pair, and an `UNSUBSCRIBE` payload must contain at least one `Topic Filter`. A packet that contains only the fixed header and Packet Identifier, with no payload elements, is malformed. wolfMQTT's decoders currently return success with `topic_count = 0`.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html).

`SUBSCRIBE` is defined in Section `3.8 SUBSCRIBE - Subscribe to topics`.

The fixed header is defined in Section `3.8.1 Fixed header`:

- Packet type is `8`.
- The required fixed-header flags are `0010`.
- A normal MQTT 3.1.1 `SUBSCRIBE` fixed header starts with `0x82`.

The variable header is defined in Section `3.8.2 Variable header`:

- It contains a Packet Identifier.
- The Packet Identifier is two bytes.

The payload is defined in Section `3.8.3 Payload`. Original English requirements:

```text
The payload of a SUBSCRIBE packet contains a list of Topic Filters indicating the Topics to which the Client wants to subscribe.
```

```text
The Topic Filters in a SUBSCRIBE packet payload MUST be UTF-8 encoded strings as defined in Section 1.5.3 [MQTT-3.8.3-1].
```

```text
The payload of a SUBSCRIBE packet MUST contain at least one Topic Filter / QoS pair [MQTT-3.8.3-3].
```

Therefore, for MQTT 3.1.1, the minimum valid `SUBSCRIBE` body after the fixed header is:

```text
Packet Identifier + one Topic Filter + one Requested QoS byte
```

`UNSUBSCRIBE` is defined in Section `3.10 UNSUBSCRIBE - Unsubscribe from topics`.

The fixed header is defined in Section `3.10.1 Fixed header`:

- Packet type is `10`.
- The required fixed-header flags are `0010`.
- A normal MQTT 3.1.1 `UNSUBSCRIBE` fixed header starts with `0xA2`.

The variable header is defined in Section `3.10.2 Variable header`:

- It contains a Packet Identifier.
- The Packet Identifier is two bytes.

The payload is defined in Section `3.10.3 Payload`. Original English requirements:

```text
The UNSUBSCRIBE Packet payload contains the list of Topic Filters that the Client wishes to unsubscribe from.
```

```text
The Topic Filters in an UNSUBSCRIBE packet MUST be UTF-8 encoded strings as defined in Section 1.5.3, packed contiguously.
```

```text
The Payload of an UNSUBSCRIBE packet MUST contain at least one Topic Filter [MQTT-3.10.3-2].
```

Therefore, for MQTT 3.1.1, the minimum valid `UNSUBSCRIBE` body after the fixed header is:

```text
Packet Identifier + one Topic Filter
```

## Expected Behavior

| Packet bytes | Meaning | Expected result |
|---|---|---|
| `82 02 00 01` | `SUBSCRIBE`, Packet Identifier only, empty payload | Reject as malformed |
| `82 06 00 01 00 01 61 00` | `SUBSCRIBE`, Packet Identifier + topic `a` + QoS 0 | Accept |
| `A2 02 00 01` | `UNSUBSCRIBE`, Packet Identifier only, empty payload | Reject as malformed |
| `A2 05 00 01 00 01 61` | `UNSUBSCRIBE`, Packet Identifier + topic `a` | Accept |

The empty-payload packets are invalid because they contain no topic element after the Packet Identifier.

## Code Description

### SUBSCRIBE decoder allows zero topic entries

File: `wolfMQTT-master/src/mqtt_packet.c:1813`

```c
/* Decode fixed header */
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_SUBSCRIBE, NULL, NULL, NULL);
```

File: `wolfMQTT-master/src/mqtt_packet.c:1825`

```c
/* Decode variable header */
if (subscribe) {
    int tmp;
    tmp = MqttDecode_Num(rx_payload, &subscribe->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

After the Packet Identifier is decoded, the decoder initializes `topic_count` to zero:

File: `wolfMQTT-master/src/mqtt_packet.c:1865`

```c
subscribe->topic_count = 0;
if (subscribe->topics == NULL) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
}
```

It then decodes topic entries only while there are payload bytes remaining:

File: `wolfMQTT-master/src/mqtt_packet.c:1870`

```c
while (rx_payload < rx_end) {
    MqttTopic *topic;
    byte options;
    if (subscribe->topic_count >= MAX_MQTT_TOPICS) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
```

If there are no payload bytes after the Packet Identifier, the loop is skipped and `topic_count` remains `0`.

File: `wolfMQTT-master/src/mqtt_packet.c:1897`

```c
/* Return total length of packet */
return header_len + remain_len;
```

There is no final check that rejects `subscribe->topic_count == 0`.

### UNSUBSCRIBE decoder allows zero topic entries

File: `wolfMQTT-master/src/mqtt_packet.c:2102`

```c
/* Decode fixed header */
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_UNSUBSCRIBE, NULL, NULL, NULL);
```

File: `wolfMQTT-master/src/mqtt_packet.c:2114`

```c
/* Decode variable header */
if (unsubscribe) {
    int tmp;
    tmp = MqttDecode_Num(rx_payload, &unsubscribe->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

After the Packet Identifier is decoded, the decoder initializes `topic_count` to zero:

File: `wolfMQTT-master/src/mqtt_packet.c:2154`

```c
unsubscribe->topic_count = 0;
if (unsubscribe->topics == NULL) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
}
```

It then decodes topic filters only while payload bytes remain:

File: `wolfMQTT-master/src/mqtt_packet.c:2159`

```c
while (rx_payload < rx_end) {
    MqttTopic *topic;
    if (unsubscribe->topic_count >= MAX_MQTT_TOPICS) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
```

If the payload is empty after the Packet Identifier, the loop is skipped and `topic_count` remains `0`.

File: `wolfMQTT-master/src/mqtt_packet.c:2180`

```c
/* Return total length of packet */
return header_len + remain_len;
```

There is no final check that rejects `unsubscribe->topic_count == 0`.

### Encoding side does not provide equivalent receive-side protection

The encoders build the Remaining Length from the configured `topic_count`.

File: `wolfMQTT-master/src/mqtt_packet.c:1719`

```c
/* Determine packet length */
remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
for (i = 0; i < subscribe->topic_count; i++) {
```

File: `wolfMQTT-master/src/mqtt_packet.c:2014`

```c
/* Determine packet length */
remain_len = MQTT_DATA_LEN_SIZE; /* For packet_id */
for (i = 0; i < unsubscribe->topic_count; i++) {
```

These loops can produce a packet containing only a Packet Identifier if the caller supplies `topic_count = 0`. More importantly for broker-side robustness, the receive decoders do not reject inbound packets that contain no topic elements.

## Reproduction

A small reproducer was added at:

`wolfMQTT-master/tests/repro_subscribe_unsubscribe_empty_payload.c`

Compile and run from `wolfMQTT-master`:

```powershell
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c tests/repro_subscribe_unsubscribe_empty_payload.c -o tests/repro_subscribe_unsubscribe_empty_payload.exe
.\tests\repro_subscribe_unsubscribe_empty_payload.exe
```

Observed output:

```text
empty SUBSCRIBE payload
  decode rc: 4
  accepted: yes
  packet_id: 1
  topic_count: 0
valid SUBSCRIBE payload
  decode rc: 8
  accepted: yes
  packet_id: 1
  topic_count: 1
empty UNSUBSCRIBE payload
  decode rc: 4
  accepted: yes
  packet_id: 1
  topic_count: 0
valid UNSUBSCRIBE payload
  decode rc: 7
  accepted: yes
  packet_id: 1
  topic_count: 1
repro verdict: issue reproduced: empty SUBSCRIBE/UNSUBSCRIBE payloads were accepted
```

The malformed packets are accepted with `topic_count = 0`.

## Inconsistency Reason

The standard defines a minimum payload cardinality:

- `SUBSCRIBE` must contain at least one `Topic Filter / QoS` pair.
- `UNSUBSCRIBE` must contain at least one `Topic Filter`.

The implementation decodes topic entries using a loop that runs only while payload bytes remain. If no payload bytes remain after the Packet Identifier, the loop simply does not run, and the decoder returns success.

The mismatch is:

- Standard: empty `SUBSCRIBE` and `UNSUBSCRIBE` payloads are malformed.
- Code behavior: empty payloads decode successfully with `topic_count = 0`.
- Missing invariant: after decoding, `topic_count` must be greater than zero.

## Suggested Fix Direction

After decoding the payload loop, the decoders should reject zero topic entries:

```c
if (subscribe->topic_count == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

```c
if (unsubscribe->topic_count == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would enforce the MQTT 3.1.1 minimum payload element requirement on the receive path.
