# ID4/ID5 Analysis: Invalid SUBSCRIBE / UNSUBSCRIBE Fixed-Header Flags Do Not Trigger Malformed Close

## Scope

This note verifies the following two reported issues:

- ID4 (`source_idx=3`): invalid fixed-header reserved-bit values can pass through the decode path, and the broker does not perform the required `malformed + close` behavior.
- ID5 (`source_idx=4`): invalid fixed-header reserved-bit values do not trigger protocol-violation disconnection.

These two findings are closely related to ID11/ID13. ID11/ID13 emphasize the missing reserved-bit validation itself; ID4/ID5 emphasize the consequence: the malformed packet is not rejected by closing the network connection.

## English Normative Requirements (MQTT v3.1.1)

Source document: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`

General invalid fixed-header flag rule (`[MQTT-2.2.2-2]`):

```text
If invalid flags are received, the receiver MUST close the Network Connection
[MQTT-2.2.2-2].
```

SUBSCRIBE fixed-header rule (`[MQTT-3.8.1-1]`):

```text
Bits 3,2,1 and 0 of the fixed header of the SUBSCRIBE Control Packet are
reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any
other value as malformed and close the Network Connection [MQTT-3.8.1-1].
```

UNSUBSCRIBE fixed-header rule (`[MQTT-3.10.1-1]`):

```text
Bits 3,2,1 and 0 of the fixed header of the UNSUBSCRIBE Control Packet are
reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any
other value as malformed and close the Network Connection [MQTT-3.10.1-1].
```

Interpretation:

- Valid SUBSCRIBE first byte: `0x82` (`type=8`, flags=`0010`).
- Invalid SUBSCRIBE examples: `0x80`, `0x81`, `0x83`, etc.
- Valid UNSUBSCRIBE first byte: `0xA2` (`type=10`, flags=`0010`).
- Invalid UNSUBSCRIBE examples: `0xA0`, `0xA1`, `0xA3`, etc.
- For invalid values, the required behavior is not merely "decode failure"; the server must treat the packet as malformed and close the network connection.

## Code Evidence

### 1) Fixed-header decoder validates only packet type

File: `wolfMQTT-master/src/mqtt_packet.c`

```c
static int MqttDecode_FixedHeader(byte *rx_buf, int rx_buf_len, int *remain_len,
    byte type, MqttQoS *p_qos, byte *p_retain, byte *p_duplicate)
{
    int header_len;
    MqttPacket* header = (MqttPacket*)rx_buf;

    /* Decode the length remaining */
    header_len = MqttDecode_Vbi(header->len, (word32*)remain_len, rx_buf_len);
    if (header_len < 0) {
        return header_len;
    }

    /* Validate packet type */
    if (MQTT_PACKET_TYPE_GET(header->type_flags) != type) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
    }

    /* Extract header flags */
    if (p_qos) {
        *p_qos = (MqttQoS)MQTT_PACKET_FLAGS_GET_QOS(header->type_flags);
    }
    if (p_retain) {
        *p_retain = (MQTT_PACKET_FLAGS_GET(header->type_flags) &
            MQTT_PACKET_FLAG_RETAIN) ? 1 : 0;
    }
    if (p_duplicate) {
        *p_duplicate = (MQTT_PACKET_FLAGS_GET(header->type_flags) &
            MQTT_PACKET_FLAG_DUPLICATE) ? 1 : 0;
    }

    header_len += sizeof(header->type_flags); /* Add size of type and flags */

    (void)rx_buf_len;

    return header_len;
}
```

The decoder checks only the high-nibble packet type:

```text
MQTT_PACKET_TYPE_GET(header->type_flags) == type
```

It does not check that the low nibble is exactly `0x2` for SUBSCRIBE or UNSUBSCRIBE. Therefore, `0x80` can still be accepted as a SUBSCRIBE packet type, and `0xA0` can still be accepted as an UNSUBSCRIBE packet type.

### 2) SUBSCRIBE decode does not request or validate fixed-header flags

File: `wolfMQTT-master/src/mqtt_packet.c`

```c
/* Decode fixed header */
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_SUBSCRIBE, NULL, NULL, NULL);
if (header_len < 0) {
    return header_len;
}
if (rx_buf_len < header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
rx_payload = &rx_buf[header_len];
rx_end = rx_payload + remain_len;
```

The caller passes `NULL, NULL, NULL` for QoS, retain, and duplicate outputs. Because no flag output is requested and no explicit low-nibble comparison is performed, malformed SUBSCRIBE flags do not cause this function to return an error.

### 3) UNSUBSCRIBE decode has the same gap

File: `wolfMQTT-master/src/mqtt_packet.c`

```c
/* Decode fixed header */
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_UNSUBSCRIBE, NULL, NULL, NULL);
if (header_len < 0) {
    return header_len;
}
if (rx_buf_len < header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
rx_payload = &rx_buf[header_len];
rx_end = rx_payload + remain_len;
```

Like SUBSCRIBE, the UNSUBSCRIBE path validates the packet type but not the required fixed-header low nibble `0010`.

### 4) Broker dispatch ignores handler return values

File: `wolfMQTT-master/src/mqtt_broker.c`

```c
case MQTT_PACKET_TYPE_SUBSCRIBE:
    (void)BrokerHandle_Subscribe(bc, rc, broker);
    break;
case MQTT_PACKET_TYPE_UNSUBSCRIBE:
    (void)BrokerHandle_Unsubscribe(bc, rc, broker);
    break;
```

The return values of `BrokerHandle_Subscribe(...)` and `BrokerHandle_Unsubscribe(...)` are explicitly discarded. This means the dispatch path does not enforce a generic "handler returned protocol error, now close the connection" rule for these packet types.

In the current code, malformed fixed-header flags do not even become a handler error because the decode layer accepts them. But this dispatch pattern also shows that the required close behavior is not centrally enforced for these handlers.

### 5) The normal read-error path can close the connection, but invalid flags do not reach it

File: `wolfMQTT-master/src/mqtt_broker.c`

```c
/* Try non-blocking read (timeout=0) */
rc = MqttPacket_Read(&bc->client, bc->rx_buf, BROKER_CLIENT_RX_SZ(bc), 0);

if (rc == MQTT_CODE_ERROR_TIMEOUT || rc == MQTT_CODE_CONTINUE) {
    /* No data available - not an error */
    rc = 0;
}
else if (rc < 0) {
    WBLOG_ERR(broker, "broker: read failed sock=%d rc=%d", (int)bc->sock, rc);
    BrokerClient_PublishWill(broker, bc); /* abnormal disconnect */
    /* Session persistence: keep subs if clean_session=0 */
    if (bc->clean_session) {
        BrokerSubs_RemoveClient(broker, bc);
    }
    else {
        BrokerSubs_OrphanClient(broker, bc);
    }
    BrokerClient_Remove(broker, bc);
    return 0;
}
```

This branch closes/removes the client only when `MqttPacket_Read(...)` returns an error. However, SUBSCRIBE/UNSUBSCRIBE invalid reserved flags are not rejected by the fixed-header decoder, so they are not guaranteed to enter this close path.

## Why the Inconsistency Exists

The MQTT standard combines the validation and the consequence:

```text
invalid fixed-header flags -> malformed packet -> close the Network Connection
```

The inspected code instead behaves like this:

```text
invalid SUBSCRIBE/UNSUBSCRIBE low nibble
-> packet type high nibble still matches
-> fixed-header decode succeeds
-> handler continues parsing
-> broker dispatch ignores handler return value
-> no required malformed+close behavior
```

So ID4 and ID5 are valid, but they are not independent from ID11/ID13:

- ID4 is the malformed-close consequence of missing SUBSCRIBE fixed-header flag validation.
- ID5 is the malformed-close consequence of missing UNSUBSCRIBE fixed-header flag validation.

## Final Conclusion

ID4 and ID5 describe a real protocol-compliance gap in `wolfMQTT-master`.

The implementation does not strictly reject invalid SUBSCRIBE/UNSUBSCRIBE fixed-header reserved bits, and therefore malformed packets such as `0x80` or `0xA0` can pass through the receive/decode path without triggering the MQTT v3.1.1 required network-connection close.

In short:

```text
ID4 ~= ID11: SUBSCRIBE reserved bits not validated, so malformed+close is missing.
ID5 ~= ID13: UNSUBSCRIBE reserved bits not validated, so malformed+close is missing.
```

