# Invalid UNSUBSCRIBE Fixed-Header Flags Do Not Trigger Malformed Close

## Summary

This document shows that invalid UNSUBSCRIBE fixed-header flags can pass through wolfMQTT's receive path because the decoder checks the packet type but not the required low-nibble value `0010`. As a result, malformed UNSUBSCRIBE packets such as `0xA0` may avoid the MQTT 3.1.1 required malformed-packet rejection and network-connection close.

## English Normative Requirements (MQTT v3.1.1)

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), Sections 2.2.2 and 3.10.1.

General invalid fixed-header flag rule (`[MQTT-2.2.2-2]`):

```text
If invalid flags are received, the receiver MUST close the Network Connection
[MQTT-2.2.2-2].
```

UNSUBSCRIBE fixed-header rule (`[MQTT-3.10.1-1]`):

```text
Bits 3,2,1 and 0 of the fixed header of the UNSUBSCRIBE Control Packet are
reserved and MUST be set to 0,0,1 and 0 respectively. The Server MUST treat any
other value as malformed and close the Network Connection [MQTT-3.10.1-1].
```

Interpretation:

- Valid UNSUBSCRIBE first byte: `0xA2` (`type=10`, flags=`0010`).
- Invalid UNSUBSCRIBE examples: `0xA0`, `0xA1`, `0xA3`, etc.
- For invalid values, the required behavior is not merely "decode failure"; the server must treat the packet as malformed and close the network connection.

## Code Evidence

### 1. Fixed-header decoder validates only packet type

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

It does not check that the low nibble is exactly `0x2` for UNSUBSCRIBE. Therefore, `0xA0` can still be accepted as an UNSUBSCRIBE packet type even though the fixed-header flags are invalid.

### 2. UNSUBSCRIBE decode does not request or validate fixed-header flags

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

The caller passes `NULL, NULL, NULL` for QoS, retain, and duplicate outputs. Because no flag output is requested and no explicit low-nibble comparison is performed, malformed UNSUBSCRIBE flags do not cause this function to return an error.

### 3. Broker dispatch ignores the UNSUBSCRIBE handler return value

File: `wolfMQTT-master/src/mqtt_broker.c`

```c
case MQTT_PACKET_TYPE_UNSUBSCRIBE:
    (void)BrokerHandle_Unsubscribe(bc, rc, broker);
    break;
```

The return value of `BrokerHandle_Unsubscribe(...)` is explicitly discarded. This means the dispatch path does not enforce a generic "handler returned protocol error, now close the connection" rule for UNSUBSCRIBE.

In the current code, malformed fixed-header flags do not even become a handler error because the decode layer accepts them. But this dispatch pattern also shows that the required close behavior is not centrally enforced for this handler.

### 4. The normal read-error path can close the connection, but invalid UNSUBSCRIBE flags do not reach it

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

This branch closes/removes the client only when `MqttPacket_Read(...)` returns an error. However, invalid UNSUBSCRIBE reserved flags are not rejected by the fixed-header decoder, so they are not guaranteed to enter this close path.

## Why the Inconsistency Exists

The MQTT standard combines the validation and the consequence:

```text
invalid UNSUBSCRIBE fixed-header flags -> malformed packet -> close the Network Connection
```

The inspected code instead behaves like this:

```text
invalid UNSUBSCRIBE low nibble
-> packet type high nibble still matches
-> fixed-header decode succeeds
-> handler continues parsing
-> broker dispatch ignores handler return value
-> no required malformed+close behavior
```

## Final Conclusion

The UNSUBSCRIBE malformed-close issue describes a real protocol-compliance gap in `wolfMQTT-master`.

The implementation does not strictly reject invalid UNSUBSCRIBE fixed-header reserved bits, and therefore malformed packets such as `0xA0` can pass through the receive/decode path without triggering the MQTT v3.1.1 required network-connection close.

In short:

```text
UNSUBSCRIBE malformed-close issue ~= UNSUBSCRIBE reserved bits not validated, so malformed+close is missing.
```
