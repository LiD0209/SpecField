# CONNACK Flags Receive-Side Validation Is Insufficient

## Summary

This document shows that wolfMQTT's broker sends legal CONNACK flags, but the client-side receive decoder does not validate that reserved CONNACK flag bits are zero. The result is a partial-compliance issue: outbound behavior is mostly correct, while malformed received CONNACK packets can be accepted without enforcing MQTT 3.1.1 protocol-violation handling.

Checked materials:

- Standard: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), Sections 3.2 and 4.8.
- Codebase: `wolfMQTT-master`

## English Standard Text

The relevant MQTT 3.1.1 rules are in Section `3.2 CONNACK - Acknowledge connection request` and Section `4.8 Handling errors`.

### CONNACK packet direction

Original English text from Section `3.2`:

```text
The CONNACK Packet is the packet sent by the Server in response to a CONNECT Packet received from a Client.
```

This establishes the direction of the packet:

```text
Server / Broker -> Client
```

Therefore, the CONNACK flags validation issue is primarily a client-side receive/decode issue. It is not about whether wolfMQTT's broker sends malformed CONNACK packets.

### CONNACK must be the first server packet

Original English text from `[MQTT-3.2.0-1]`:

```text
The first packet sent from the Server to the Client MUST be a CONNACK Packet.
```

This means a client implementation needs to parse the CONNACK packet as the first server response to CONNECT.

### Connect Acknowledge Flags format

Original English text from Section `3.2.2 Variable header`:

```text
Byte 1 is the "Connect Acknowledge Flags".
Bits 7-1 are reserved and MUST be set to 0.
Bit 0 (SP1) is the Session Present Flag.
```

The required bit layout is:

| Bit range | Meaning | Required value |
|---|---|---|
| bit 0 | Session Present | `0` or `1` depending on session state |
| bits 7-1 | Reserved | MUST be `0` |

So the only valid MQTT 3.1.1 CONNACK Flags byte values are:

| Flags value | Meaning | Validity |
|---:|---|---|
| `0x00` | Session Present = 0 | valid |
| `0x01` | Session Present = 1 | valid |

Any value with bits 7-1 set is invalid, for example:

| Flags value | Reason |
|---:|---|
| `0x02` | bit 1 is set, but bit 1 is reserved |
| `0x80` | bit 7 is set, but bit 7 is reserved |
| `0xFE` | all reserved bits are set |
| `0xFF` | all reserved bits are set, plus Session Present is set |

### Non-zero return code requires Session Present = 0

Original English text from `[MQTT-3.2.2-4]`:

```text
If a server sends a CONNACK packet containing a non-zero return code it MUST set Session Present to 0.
```

This adds another receive-side consistency rule:

- If `return_code != 0x00`, then `flags & 0x01` must be `0`.
- In other words, refused CONNACK packets must not claim an existing session.

### Protocol violation handling

Original English text from `[MQTT-4.8.0-1]`:

```text
Unless stated otherwise, if either the Server or Client encounters a protocol violation, it MUST close the Network Connection on which it received that Control Packet which caused the protocol violation.
```

Combining the CONNACK flags rule with the general error-handling rule:

- A CONNACK with bits 7-1 set is a protocol violation.
- A client receiving that invalid CONNACK must close the Network Connection.
- A CONNACK with non-zero return code and Session Present set is also invalid under `[MQTT-3.2.2-4]`.

## Expected Behavior

When wolfMQTT acts as an MQTT 3.1.1 client and receives a CONNACK packet, the decoder or caller should reject invalid CONNACK flags.

Expected checks include:

```c
if ((connect_ack->flags & 0xFE) != 0) {
    /* Reserved bits 7-1 are non-zero: protocol violation. */
    return MQTT_CODE_ERROR_MALFORMED_DATA;
}

if (connect_ack->return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED &&
        (connect_ack->flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) != 0) {
    /* Refused CONNACK must have Session Present set to 0. */
    return MQTT_CODE_ERROR_MALFORMED_DATA;
}
```

The exact internal error code may vary, but the observable behavior should be that the client does not accept the invalid CONNACK as a normal decoded packet and the connection is closed according to the protocol violation rule.

## Code Description

### 1. The broker sending path sets CONNACK flags to zero

File: `wolfMQTT-master/src/mqtt_broker.c:2917`

```c
ack.flags = 0;
ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
```

File: `wolfMQTT-master/src/mqtt_broker.c:3023`

```c
rc = MqttEncode_ConnectAck(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &ack);
```

This means wolfMQTT's broker-side normal CONNACK send path uses `flags = 0`, which satisfies the reserved-bit requirement for the packets it sends.

So the issue is not:

```text
wolfMQTT broker sends illegal CONNACK flags
```

The issue is:

```text
wolfMQTT client/decoder accepts received CONNACK flags without validating reserved bits
```

### 2. The CONNACK encoder writes whatever flags value is provided

File: `wolfMQTT-master/src/mqtt_packet.c:1263`

```c
*tx_payload++ = connect_ack->flags;
*tx_payload++ = connect_ack->return_code;
```

The encoder is a generic packet encoder. It writes `connect_ack->flags` directly. In the broker path this is safe because the broker initializes `ack.flags = 0`.

However, the encoder itself also does not enforce:

```text
flags must be 0x00 or 0x01
```

This is less important than the receive path, but it shows that the protocol constraint is not centralized in the packet layer.

### 3. The CONNACK decoder reads flags but does not validate them

File: `wolfMQTT-master/src/mqtt_packet.c:1149`

```c
int MqttDecode_ConnectAck(byte *rx_buf, int rx_buf_len,
    MqttConnectAck *connect_ack)
```

File: `wolfMQTT-master/src/mqtt_packet.c:1167`

```c
if (remain_len < 2) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This function validates that the CONNACK remaining length is at least large enough to contain the flags and return code.

File: `wolfMQTT-master/src/mqtt_packet.c:1176`

```c
connect_ack->flags = *rx_payload++;
connect_ack->return_code = *rx_payload++;
```

But after reading the flags byte, the function does not check:

```c
(connect_ack->flags & 0xFE) == 0
```

It also does not check:

```c
return_code != 0x00 implies Session Present == 0
```

Therefore, a malformed CONNACK such as:

```text
20 02 FF 00
```

would be decoded as:

| Field | Value |
|---|---:|
| Packet type | `0x20` (`CONNACK`) |
| Remaining Length | `0x02` |
| Flags | `0xFF` |
| Return Code | `0x00` (`Accepted`) |

The flags value `0xFF` is invalid because bits 7-1 are reserved and must be zero, but the decoder stores it without rejecting the packet.

### 4. The client read path does not add the missing flags validation

File: `wolfMQTT-master/src/mqtt_client.c:658`

```c
rc = MqttDecode_ConnectAck(rx_buf, rx_len, p_connect_ack);
```

After decoding, the client handles MQTT 5 properties if enabled, then returns to the CONNECT flow.

File: `wolfMQTT-master/src/mqtt_client.c:1900`

```c
if (rc == MQTT_CODE_SUCCESS &&
        mc_connect->ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
    rc = MQTT_TRACE_ERROR(MQTT_CODE_ERROR_CONNECT_REFUSED);
}
```

The client checks whether the CONNACK return code indicates refusal. It does not check whether the CONNACK flags byte is valid.

So if a server sends invalid CONNACK flags with return code `0x00`, the client can treat the CONNACK as a successful connection response.

### 5. The public constants define only Session Present

File: `wolfMQTT-master/wolfmqtt/mqtt_packet.h:367`

```c
/* CONNECT ACKNOWLEDGE */
/* Connect Ack flags */
enum MqttConnectAckFlags {
    MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT = 0x01
};
```

Only bit 0 has a defined meaning. There is no mask or helper for rejecting reserved bits 7-1, such as:

```c
#define MQTT_CONNECT_ACK_FLAG_RESERVED_MASK 0xFE
```

This is not a violation by itself, but it matches the implementation behavior: the code has a constant for the valid bit, but no explicit validation that all other bits are zero.

## Inconsistency Reason

The standard defines a structural constraint on the CONNACK Flags byte:

```text
Bits 7-1 are reserved and MUST be set to 0.
```

The standard also defines the required error behavior for protocol violations:

```text
Client or Server encounters a protocol violation -> MUST close the Network Connection.
```

wolfMQTT partially implements the rule:

- When wolfMQTT acts as a broker, it sends `ack.flags = 0`.
- That satisfies the outgoing CONNACK flags constraint for the normal broker path.

But wolfMQTT does not fully implement the receive-side rule:

- `MqttDecode_ConnectAck()` reads the flags byte.
- It does not reject values outside `0x00` and `0x01`.
- The client connect flow checks the return code, but not the reserved flags bits.
- Therefore the client can accept a CONNACK packet that violates the MQTT 3.1.1 CONNACK flags rule.

This is why the issue is best classified as:

```text
Partially satisfied
```

not fully unsatisfied:

- Send-side behavior is compliant in the broker path.
- Receive-side validation is incomplete in the client/decoder path.

## Impact

The practical impact is limited but real:

- A malformed broker response can pass through `MqttDecode_ConnectAck()` as if it were structurally valid.
- The client may treat `CONNACK flags = 0x02`, `0x80`, `0xFE`, or `0xFF` as a normal decoded CONNACK.
- This weakens protocol-conformance checks and makes fuzzing results look inconsistent: illegal reserved bits are not surfaced as malformed data.

This issue is lower risk than server-side acceptance of invalid CONNECT fields, because it affects wolfMQTT acting as a client against a malformed or malicious broker response. Still, it is a real standards conformance gap for receive-side packet validation.

## Suggested Fix Direction

A focused fix would be to validate CONNACK flags in `MqttDecode_ConnectAck()` immediately after reading the flags and return code:

```c
connect_ack->flags = *rx_payload++;
connect_ack->return_code = *rx_payload++;

if ((connect_ack->flags & (byte)~MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) != 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}

if (connect_ack->return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED &&
        (connect_ack->flags & MQTT_CONNECT_ACK_FLAG_SESSION_PRESENT) != 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would align the decoder with:

- the reserved-bit rule in Section `3.2.2`;
- the non-zero return-code/session-present rule `[MQTT-3.2.2-4]`;
- the general protocol violation handling rule `[MQTT-4.8.0-1]`.

## Conclusion

The CONNACK flags receive-side validation issue is a valid partial-compliance issue.

The precise conclusion is:

```text
wolfMQTT's broker send path sets CONNACK flags to zero and is compliant for outgoing CONNACK packets. However, wolfMQTT's client-side CONNACK decoder does not validate that received CONNACK reserved bits 7-1 are zero, and the client connect path does not close the connection on that protocol violation.
```

Therefore, the issue should be documented as a receive-side validation gap, not as a broker-side CONNACK encoding error.
