# SUBSCRIBE / UNSUBSCRIBE Fixed-Header Reserved Bits

## Summary

This document shows that wolfMQTT's inbound SUBSCRIBE and UNSUBSCRIBE paths do not strictly validate the fixed-header reserved bits required by MQTT 3.1.1. The shared fixed-header decoder checks only the packet type, while the specific decode paths pass no flag outputs and the broker dispatch does not centrally enforce malformed-packet connection closure.

## English Normative Requirements (MQTT v3.1.1)

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), Sections 2.2.2, 3.8.1, and 3.10.1.
(section numbers above identify the online normative text).

General fixed-header flag rule (`[MQTT-2.2.2-2]`):

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

- SUBSCRIBE first byte must be `0x82` (`type=8`, flags=`0010`).
- UNSUBSCRIBE first byte must be `0xA2` (`type=10`, flags=`0010`).
- Any other low nibble, for example `0x80` or `0xA0`, is malformed and must trigger disconnect.

## Code Behavior in `wolfMQTT-master`

### 1) Fixed-header decode checks packet type, not the required low-nibble constant

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

The function validates only the high-nibble packet type. It can extract flags if the caller asks, but it does not enforce packet-specific reserved-bit constants such as `flags == 0x2` for SUBSCRIBE/UNSUBSCRIBE.

### 2) SUBSCRIBE / UNSUBSCRIBE decode passes `NULL` for all flag outputs

File: `wolfMQTT-master/src/mqtt_packet.c`

```c
/* Decode fixed header */
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_SUBSCRIBE, NULL, NULL, NULL);
if (header_len < 0) {
    return header_len;
}
```

```c
/* Decode fixed header */
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_UNSUBSCRIBE, NULL, NULL, NULL);
if (header_len < 0) {
    return header_len;
}
```

Because all flag outputs are `NULL`, these decode paths do not even read the low-nibble flags into a local variable, so no fixed-header reserved-bit validation can occur in these handlers.

### 3) Broker dispatch ignores SUBSCRIBE/UNSUBSCRIBE handler return values

File: `wolfMQTT-master/src/mqtt_broker.c`

```c
case MQTT_PACKET_TYPE_SUBSCRIBE:
    (void)BrokerHandle_Subscribe(bc, rc, broker);
    break;
case MQTT_PACKET_TYPE_UNSUBSCRIBE:
    (void)BrokerHandle_Unsubscribe(bc, rc, broker);
    break;
```

Even if a future decode-layer check returned an error here, this dispatch branch currently discards the handler return value. That weakens the required "malformed + close connection" behavior for protocol violations.

### 4) Sending path uses the correct fixed-header constant

File: `wolfMQTT-master/src/mqtt_packet.c`

```c
/* Encode fixed header */
header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
    MQTT_PACKET_TYPE_SUBSCRIBE, 0, MQTT_QOS_1, 0);
if (header_len < 0) {
```

```c
/* Encode fixed header */
header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
    MQTT_PACKET_TYPE_UNSUBSCRIBE, 0, MQTT_QOS_1, 0);
if (header_len < 0) {
```

Outbound construction is compliant: QoS1 in the fixed header gives low nibble `0010`, producing `0x82` for SUBSCRIBE and `0xA2` for UNSUBSCRIBE. The gap is on inbound validation and violation handling.

## Why the Inconsistency Exists

1. Validation granularity mismatch:
- Implementation validates packet type (`high nibble`) but does not validate the required reserved-bit pattern (`low nibble`) for SUBSCRIBE/UNSUBSCRIBE.

2. Decode caller mismatch:
- SUBSCRIBE and UNSUBSCRIBE call `MqttDecode_FixedHeader(...)` with flag outputs set to `NULL`, so the required flags are not available for checking in those functions.

3. Error-handling gap in broker dispatch:
- SUBSCRIBE/UNSUBSCRIBE handler return codes are ignored at the dispatch site, so malformed-packet close semantics are not enforced by this branch.

## Final Conclusion

The two reported issues are valid:

- The inbound SUBSCRIBE path does not strictly check that fixed-header low 4 bits are `0010`.
- The inbound UNSUBSCRIBE path does not strictly check that fixed-header low 4 bits are `0010`, and malformed-close handling is missing.

In short: **encode path compliant, decode/violation-handling path non-compliant**.
