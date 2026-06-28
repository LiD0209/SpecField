# PUBREL Fixed Header Reserved Bits Are Not Validated

## Summary

This document shows that wolfMQTT does not validate the required PUBREL fixed-header reserved-bit pattern on receive. The outbound encoder produces the correct `0x62` value, but inbound PUBREL packets with invalid low-nibble flags can still decode successfully and reach normal broker handling instead of triggering the MQTT 3.1.1 malformed-packet close behavior.

## English Standard Text

The relevant MQTT 3.1.1 rule is in `PUBREL - Publish release`, fixed header, clause `[MQTT-3.6.1-1]`.

Short original English excerpts:

```text
"MUST be set to 0,0,1 and 0 respectively"
"malformed and close the Network Connection"
```

Meaning:

- In a `PUBREL` Control Packet, fixed-header bits 3, 2, 1, and 0 are reserved.
- Their only valid value is `0010`.
- If the server receives any other value, it must treat the packet as malformed and close the network connection.

The general fixed-header flag rule also applies. In `[MQTT-2.2.2-2]`, invalid fixed-header flags require the receiver to close the network connection. The general error-handling rule `[MQTT-4.8.0-1]` also requires closing the connection when a protocol violation is received.

Short original English excerpts:

```text
"invalid flags are received"
"MUST close the Network Connection"
```

## Expected Behavior

For MQTT 3.1.1, a server receiving PUBREL must distinguish:

| First byte | Meaning | Expected result |
|---|---|---|
| `0x62` | packet type `6`, flags `0010` | valid PUBREL |
| `0x60`, `0x61`, `0x63` ... `0x6F` except `0x62` | packet type `6`, invalid flags | malformed packet, close connection |

So checking only the high 4-bit packet type is insufficient. The low 4-bit flags must also be validated.

## Code Description

### 1. Fixed header decoder checks packet type, but not required flags

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_FixedHeader()`

Relevant lines:

```c
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
```

The function validates only:

```c
MQTT_PACKET_TYPE_GET(header->type_flags) == type
```

It does not validate:

```c
MQTT_PACKET_FLAGS_GET(header->type_flags) == 0x02
```

for `MQTT_PACKET_TYPE_PUBLISH_REL`.

This means bytes like `0x60`, `0x61`, `0x63`, or `0x6F` still have packet type `6`, so they can pass the type check even though the low 4 bits are invalid for PUBREL.

### 2. PUBREL receive decoder does not request or validate flags

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_PublishResp()`

Relevant lines:

```c
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    type, NULL, NULL, NULL);
```

For PUBREL, the broker calls this function with:

```c
type = MQTT_PACKET_TYPE_PUBLISH_REL
```

But it passes `NULL` for QoS, retain, and duplicate outputs. More importantly, `MqttDecode_FixedHeader()` has no required-flags parameter and no per-packet reserved-bit table. Therefore, PUBREL fixed-header flags are not checked here.

### 3. PUBREL handler accepts the decoded packet and sends PUBCOMP

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_PublishRel()`

Relevant lines:

```c
rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
        MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
if (rc < 0) {
    WBLOG_ERR(bc->broker, "broker: PUBLISH_REL decode failed rc=%d", rc);
    return rc;
}

rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
        MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
```

If `MqttDecode_PublishResp()` succeeds, the broker sends `PUBCOMP`.

Because the decoder does not reject invalid PUBREL flags, a malformed PUBREL with packet type `6` but wrong low 4 bits can be handled as if it were valid.

### 4. The broker dispatch path discards the handler return value

File: `wolfMQTT-master/src/mqtt_broker.c`

Dispatch branch:

```c
case MQTT_PACKET_TYPE_PUBLISH_REL:
    /* QoS 2 step 3: publisher sends PUBREL, broker
     * responds with PUBCOMP */
    (void)BrokerHandle_PublishRel(bc, rc);
    break;
```

Even if the lower decode layer returned an error, this branch does not close the connection for the malformed PUBREL case. The return value is intentionally ignored.

For this specific issue, the larger problem is earlier: invalid PUBREL fixed-header flags are not detected at all. But the dispatch behavior also shows there is no explicit malformed + close path for this branch.

### 5. Outbound PUBREL encoding is correct, but inbound validation is missing

File: `wolfMQTT-master/src/mqtt_packet.c`

Outbound encoding uses QoS 1 for PUBREL:

```c
qos = (type == MQTT_PACKET_TYPE_PUBLISH_REL) ? MQTT_QOS_1 : MQTT_QOS_0;

header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len, remain_len,
    type, 0, qos, 0);
```

This generates the correct low 4 bits `0010` for outbound PUBREL. Therefore, the implementation satisfies the sending-side fixed-header value, but does not satisfy receiving-side validation.

## Inconsistency Reason

The standard requires a value-level validation of the PUBREL fixed header:

- Packet type must be PUBREL.
- Fixed-header low 4 bits must be exactly `0010`.
- Any other low 4-bit value must be treated as malformed and must close the connection.

wolfMQTT currently performs only the first part:

- It checks that the high 4 bits indicate `MQTT_PACKET_TYPE_PUBLISH_REL`.
- It does not check that the low 4 bits equal `0x02`.
- It then decodes the packet identifier and can continue to PUBCOMP generation.

Therefore, the implementation confuses "is this a PUBREL packet type?" with "is this a well-formed PUBREL fixed header?". MQTT 3.1.1 requires both checks.

## Final Conclusion

The malformed-close concern is valid because a PUBREL packet with invalid reserved bits is not explicitly treated as malformed and closed.

The receive-path acceptance concern is valid because the receive path can accept a PUBREL first byte whose high 4 bits are correct but whose low 4 bits are invalid.

The correct compliance behavior would be to reject any inbound PUBREL whose first byte is not exactly `0x62`, and to close the network connection for that protocol violation.
