# PINGREQ, PINGRESP, and DISCONNECT Nonzero Remaining Length Is Accepted

## Summary

wolfMQTT accepts malformed MQTT 3.1.1 `PINGREQ`, `PINGRESP`, and `DISCONNECT` packets with nonzero Remaining Length.

In MQTT 3.1.1, these packet types are fixed-header-only packets. They have no variable header and no payload, so their Remaining Length must be `0`. However, wolfMQTT's packet reader accepts packets such as `C0 01 00` and `E0 01 00`, and the broker dispatch path handles them as normal `PINGREQ` and `DISCONNECT` packets. The client-side `PINGRESP` decoder also accepts a non-empty `PINGRESP` such as `D0 01 00`.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html).

MQTT Remaining Length is defined by the fixed header format in Section `2.2.3 Remaining Length`. It is the number of bytes following the Remaining Length field, including bytes in the variable header and payload. Therefore, if a packet has no variable header and no payload, its Remaining Length must be exactly `0`.

PINGREQ is defined in Section `3.12 PINGREQ`.

- Section `3.12.1 Fixed header` defines the packet as type `12` with Remaining Length `0`.
- Its fixed header byte is `0xC0`: packet type `12` in the high nibble and reserved flags `0` in the low nibble.
- Its Remaining Length byte is `0x00`.
- Section `3.12.2 Variable header` states:

```text
The PINGREQ Packet has no variable header.
```

- Section `3.12.3 Payload` states:

```text
The PINGREQ Packet has no payload.
```

The complete MQTT 3.1.1 `PINGREQ` packet is therefore only:

```text
C0 00
```

DISCONNECT is defined in Section `3.14 DISCONNECT`.

- Section `3.14.1 Fixed header` defines the packet as type `14` with Remaining Length `0`.
- Its fixed header byte is `0xE0`: packet type `14` in the high nibble and reserved flags `0` in the low nibble.
- Its Remaining Length byte is `0x00`.
- Section `3.14.2 Variable header` states:

```text
The DISCONNECT Packet has no variable header.
```

- Section `3.14.3 Payload` states:

```text
The DISCONNECT Packet has no payload.
```

The complete MQTT 3.1.1 `DISCONNECT` packet is therefore only:

```text
E0 00
```

PINGRESP is defined in Section `3.13 PINGRESP`.

- Section `3.13.1 Fixed header` defines the packet as type `13` with Remaining Length `0`.
- Its fixed header byte is `0xD0`: packet type `13` in the high nibble and reserved flags `0` in the low nibble.
- Its Remaining Length byte is `0x00`.
- Section `3.13.2 Variable header` states:

```text
The PINGRESP Packet has no variable header.
```

- Section `3.13.3 Payload` states:

```text
The PINGRESP Packet has no payload.
```

The complete MQTT 3.1.1 `PINGRESP` packet is therefore only:

```text
D0 00
```

Therefore, valid MQTT 3.1.1 encodings are:

| Packet | Valid bytes |
|---|---|
| `PINGREQ` | `C0 00` |
| `PINGRESP` | `D0 00` |
| `DISCONNECT` | `E0 00` |

Packets with extra bytes after the fixed header are malformed for MQTT 3.1.1.

## Expected Behavior

| Packet bytes | Meaning | Expected result |
|---|---|---|
| `C0 00` | Valid `PINGREQ` | Accept and send `PINGRESP` |
| `C0 01 00` | `PINGREQ` with nonzero Remaining Length | Reject as malformed |
| `D0 00` | Valid `PINGRESP` | Accept as ping response |
| `D0 01 00` | `PINGRESP` with nonzero Remaining Length | Reject as malformed |
| `E0 00` | Valid `DISCONNECT` | Process normal disconnect |
| `E0 01 00` | `DISCONNECT` with nonzero Remaining Length | Reject as malformed |

The important rule is simple: these packet types must not carry variable header bytes or payload bytes.

## Code Description

### PINGREQ encoder produces an empty packet

File: `wolfMQTT-master/src/mqtt_packet.c:2357`

```c
int header_len, remain_len = 0;
```

File: `wolfMQTT-master/src/mqtt_packet.c:2364`

```c
/* Encode fixed header */
header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
    MQTT_PACKET_TYPE_PING_REQ, 0, 0, 0);
```

The sending side builds a correct `PINGREQ` with Remaining Length `0`.

### Packet reader accepts nonzero Remaining Length for these types

File: `wolfMQTT-master/src/mqtt_packet.c:2962`

```c
/* Try and decode remaining length */
if (rx_buf_len < (client->packet.header_len - (i + 1))) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
rc = MqttDecode_Vbi(header->len,
        (word32*)&client->packet.remain_len,
        rx_buf_len - (client->packet.header_len - (i + 1)));
```

File: `wolfMQTT-master/src/mqtt_packet.c:2995`

```c
/* Read remaining */
if (client->packet.remain_len > 0) {
    rc = MqttSocket_Read(client, &rx_buf[client->packet.header_len],
        remain_read, timeout_ms);
```

`MqttPacket_Read()` decodes and reads the Remaining Length bytes generically. It does not reject `PINGREQ` or `DISCONNECT` when the decoded Remaining Length is nonzero.

### Broker handles PINGREQ without checking the length

File: `wolfMQTT-master/src/mqtt_broker.c:3576`

```c
case MQTT_PACKET_TYPE_PING_REQ:
    (void)BrokerSend_PingResp(bc);
    break;
```

File: `wolfMQTT-master/src/mqtt_broker.c:2585`

```c
static int BrokerSend_PingResp(BrokerClient* bc)
{
    if (bc == NULL) {
        return MQTT_CODE_ERROR_BAD_ARG;
    }
    WBLOG_DBG(bc->broker, "broker: PINGREQ -> PINGRESP sock=%d", (int)bc->sock);
    bc->tx_buf[0] = MQTT_PACKET_TYPE_SET(MQTT_PACKET_TYPE_PING_RESP);
    bc->tx_buf[1] = 0;
    return MqttPacket_Write(&bc->client, bc->tx_buf, 2);
}
```

The broker sees the packet type and immediately sends `PINGRESP`. There is no branch that checks whether the inbound `PINGREQ` had Remaining Length `0`.

### PINGRESP decoder does not enforce empty packet format

File: `wolfMQTT-master/src/mqtt_packet.c:2389`

```c
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_PING_RESP, NULL, NULL, NULL);
if (header_len < 0) {
    return header_len;
}

if (ping) {
    /* nothing to decode */
}

/* Return total length of packet */
return header_len + remain_len;
```

`MqttDecode_Ping()` decodes `PINGRESP`, but it does not require `remain_len == 0`. A non-empty `PINGRESP` can therefore be accepted by the decoder.

### Broker handles DISCONNECT without checking the length

File: `wolfMQTT-master/src/mqtt_broker.c:3579`

```c
case MQTT_PACKET_TYPE_DISCONNECT:
    BrokerClient_ClearWill(bc); /* normal disconnect */
    /* Session persistence: keep subs if clean_session=0 */
    if (bc->clean_session) {
        BrokerSubs_RemoveClient(broker, bc);
    }
```

The broker treats the packet as a normal disconnect based on packet type. It does not validate that the MQTT 3.1.1 `DISCONNECT` packet is empty.

### MQTT 3.1.1 DISCONNECT decoder also accepts nonzero Remaining Length

File: `wolfMQTT-master/src/mqtt_packet.c:2503`

```c
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_DISCONNECT, NULL, NULL, NULL);
if (header_len < 0) {
    return header_len;
}

if (disc) {
    /* nothing to decode for v3.1.1 */
}

/* Return total length of packet */
return header_len + remain_len;
```

The decoder records `remain_len`, but it does not require `remain_len == 0` for MQTT 3.1.1.

## Reproduction

A small reproducer was added at:

`wolfMQTT-master/tests/repro_ping_disconnect_nonzero_remaining_length.c`

Compile and run from `wolfMQTT-master`:

```powershell
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c tests/repro_ping_disconnect_nonzero_remaining_length.c -o tests/repro_ping_disconnect_nonzero_remaining_length.exe
.\tests\repro_ping_disconnect_nonzero_remaining_length.exe
```

Observed output:

```text
valid PINGREQ
  packet read rc: 2
  accepted by packet reader: yes
  packet type: 12
  remaining length: 0
invalid PINGREQ with nonzero remaining length
  packet read rc: 3
  accepted by packet reader: yes
  packet type: 12
  remaining length: 1
valid DISCONNECT
  packet read rc: 2
  accepted by packet reader: yes
  packet type: 14
  remaining length: 0
invalid DISCONNECT with nonzero remaining length
  packet read rc: 3
  accepted by packet reader: yes
  packet type: 14
  remaining length: 1
valid DISCONNECT decode
  disconnect decode rc: 2
  accepted by disconnect decoder: yes
invalid DISCONNECT decode with nonzero remaining length
  disconnect decode rc: 3
  accepted by disconnect decoder: yes
valid PINGRESP decode
  pingresp decode rc: 2
  accepted by pingresp decoder: yes
invalid PINGRESP decode with nonzero remaining length
  pingresp decode rc: 3
  accepted by pingresp decoder: yes
repro verdict: issue reproduced: non-empty PINGREQ/DISCONNECT/PINGRESP packets were accepted
```

The malformed `PINGREQ` and `DISCONNECT` packets are accepted by the packet reader. The malformed `DISCONNECT` packet is also accepted by the MQTT 3.1.1 disconnect decoder. The malformed `PINGRESP` packet is accepted by the ping response decoder.

## Inconsistency Reason

The implementation has correct outbound behavior for `PINGREQ`, and broker outbound `PINGRESP` is also encoded as an empty fixed-header-only packet. The missing piece is inbound format validation.

The mismatch is:

- Standard: `PINGREQ`, `PINGRESP`, and MQTT 3.1.1 `DISCONNECT` have no variable header and no payload, so Remaining Length must be `0`.
- Packet reader: reads nonzero Remaining Length generically and returns success.
- Broker dispatch: handles packet type `PINGREQ` and `DISCONNECT` directly without checking Remaining Length.
- Disconnect decoder: returns success for MQTT 3.1.1 `DISCONNECT` even when Remaining Length is nonzero.
- Ping response decoder: returns success for `PINGRESP` even when Remaining Length is nonzero.

As a result, malformed packets with extra bytes can enter normal broker behavior.

## Suggested Fix Direction

The broker receive path should reject non-empty `PINGREQ` and MQTT 3.1.1 `DISCONNECT` packets before normal handling:

```c
if (type == MQTT_PACKET_TYPE_PING_REQ && bc->client.packet.remain_len != 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}

if (type == MQTT_PACKET_TYPE_DISCONNECT && bc->protocol_level < MQTT_CONNECT_PROTOCOL_LEVEL_5 &&
    bc->client.packet.remain_len != 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The MQTT 3.1.1 `MqttDecode_Disconnect()` path should also enforce:

```c
if (remain_len != 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The `MqttDecode_Ping()` path should enforce the same rule for `PINGRESP`:

```c
if (remain_len != 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would align receive-side behavior with the fixed-header-only packet format required by MQTT 3.1.1.
