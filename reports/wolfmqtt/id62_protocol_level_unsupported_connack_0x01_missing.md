# Unsupported Protocol Level Is Not Rejected with CONNACK 0x01

## Summary

This document shows that wolfMQTT decodes and stores the client-supplied MQTT Protocol Level but does not consistently reject unsupported values with CONNACK return code `0x01` followed by disconnect. Unsupported Protocol Level values can enter the accepted connection path, which is a high-risk MQTT 3.1.1 compliance gap.

Checked materials:

- Standard: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), Sections 3.1.2.2 and 3.2.2.3.
- Codebase: `wolfMQTT-master`

## English Standard Text

The relevant MQTT 3.1.1 rule is in Section `3.1.2.2 Protocol Level`, clause `[MQTT-3.1.2-2]`.

Original English text:

```text
The value of the Protocol Level field for the version 3.1.1 of the protocol is 4 (0x04).
```

Original English requirement:

```text
The Server MUST respond to the CONNECT Packet with a CONNACK return code 0x01
(unacceptable protocol level) and then disconnect the Client if the Protocol
Level is not supported by the Server [MQTT-3.1.2-2].
```

The required behavior is therefore:

| Condition | Required response |
|---|---|
| Client sends supported Protocol Level | Continue CONNECT validation |
| Client sends unsupported Protocol Level | Send CONNACK return code `0x01` |
| After sending `0x01` | Disconnect the client |

The CONNACK return code table in Section `3.2.2.3 Connect Return code` also defines `0x01` as:

```text
0x01 Connection Refused, unacceptable protocol version
```

This is a MUST-level rule. It is not optional and it is different from malformed packet handling. An unsupported Protocol Level is a specific CONNECT rejection condition with a specific CONNACK return code.

## Expected Behavior

For an MQTT 3.1.1 broker that supports Protocol Level `4`:

1. Receive a CONNECT packet with Protocol Name `"MQTT"`.
2. Read the Protocol Level byte.
3. If the level is not supported, send:

```text
20 02 00 01
```

This is:

| Byte(s) | Meaning |
|---|---|
| `20` | CONNACK fixed header |
| `02` | Remaining Length |
| `00` | Connect Acknowledge Flags |
| `01` | Return code: unacceptable protocol level |

4. Close the Network Connection after sending the non-zero CONNACK.

If wolfMQTT is built with MQTT 5 support, Protocol Level `5` may be supported for MQTT 5. However, other unsupported values, such as `3` or `6`, still need to be rejected rather than treated as acceptable protocol versions.

## Code Description

### 1. Constants exist for supported protocol levels and the required return code

File: `wolfMQTT-master/wolfmqtt/mqtt_packet.h:341`

```c
#define MQTT_CONNECT_PROTOCOL_NAME_LEN  4
#define MQTT_CONNECT_PROTOCOL_NAME      "MQTT"
#define MQTT_CONNECT_PROTOCOL_LEVEL_4   4 /* v3.1.1 */
#define MQTT_CONNECT_PROTOCOL_LEVEL_5   5 /* v5.0 */
```

File: `wolfMQTT-master/wolfmqtt/mqtt_packet.h:373`

```c
enum MqttConnectAckReturnCodes {
    /* Connection accepted */
    MQTT_CONNECT_ACK_CODE_ACCEPTED = 0,

    /* The Server does not support the level of the MQTT protocol requested
       by the Client */
    MQTT_CONNECT_ACK_CODE_REFUSED_PROTO = 1,
```

So the codebase already has:

- a constant for MQTT 3.1.1 Protocol Level `4`;
- a constant for MQTT 5 Protocol Level `5`;
- a CONNACK return code constant for unacceptable protocol level: `MQTT_CONNECT_ACK_CODE_REFUSED_PROTO`.

The issue is not that constants are absent. The issue is that the broker CONNECT path does not use them to reject unsupported levels.

### 2. CONNECT decoder checks protocol name but not Protocol Level support

File: `wolfMQTT-master/src/mqtt_packet.c:986`

```c
tmp = MqttDecode_Num(packet.protocol_len, &protocol_len,
    MQTT_DATA_LEN_SIZE);
if (tmp < 0) {
    return tmp;
}
if ((protocol_len != MQTT_CONNECT_PROTOCOL_NAME_LEN) ||
    (XMEMCMP(packet.protocol_name, MQTT_CONNECT_PROTOCOL_NAME,
        MQTT_CONNECT_PROTOCOL_NAME_LEN) != 0)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This code validates that the Protocol Name is `"MQTT"`.

File: `wolfMQTT-master/src/mqtt_packet.c:997`

```c
mc_connect->protocol_level = packet.protocol_level;
```

The Protocol Level byte is copied into `mc_connect->protocol_level`, but the decoder does not reject unsupported values.

This means values such as:

```text
0x03
0x06
0x7F
```

can leave `MqttDecode_Connect()` as decoded CONNECT data rather than being mapped to `CONNACK 0x01`.

### 3. MQTT 5 property parsing uses `>= 5`, not exact supported-version validation

File: `wolfMQTT-master/src/mqtt_packet.c:1013`

```c
if (mc_connect->protocol_level >= MQTT_CONNECT_PROTOCOL_LEVEL_5) {
    /* Decode Length of Properties */
```

This is important because it shows that Protocol Level is used as a mode switch:

```text
level >= 5 -> parse MQTT 5-style properties
```

But MQTT 5 support does not imply that every level greater than or equal to `5` is valid. For example, Protocol Level `6` is not MQTT 3.1.1 and is not MQTT 5.0. A broker should not accept it as a supported protocol level.

### 4. Broker stores the decoded Protocol Level without validating support

File: `wolfMQTT-master/src/mqtt_broker.c:2694`

```c
rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
if (rc < 0) {
    WBLOG_ERR(broker, "broker: CONNECT decode failed rc=%d", rc);
    ...
    return rc;
}
```

If the CONNECT packet is decodable, broker processing continues.

File: `wolfMQTT-master/src/mqtt_broker.c:2736`

```c
bc->protocol_level = mc.protocol_level;
bc->keep_alive_sec = mc.keep_alive_sec;
bc->last_rx = WOLFMQTT_BROKER_GET_TIME_S();
```

The broker stores the client-supplied Protocol Level directly.

There is no check equivalent to:

```c
if (mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_4
#ifdef WOLFMQTT_V5
        && mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_5
#endif
        ) {
    ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_PROTO;
    goto send_connack;
}
```

### 5. Default CONNACK return code is accepted

File: `wolfMQTT-master/src/mqtt_broker.c:2917`

```c
ack.flags = 0;
ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
```

Because there is no earlier unsupported Protocol Level rejection branch, the default accepted return code remains in effect for unsupported levels.

File: `wolfMQTT-master/src/mqtt_broker.c:3023`

```c
rc = MqttEncode_ConnectAck(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &ack);
```

The broker sends the CONNACK with the current `ack.return_code`.

File: `wolfMQTT-master/src/mqtt_broker.c:3043`

```c
if (ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
    return 0;
}
return rc;
```

Only non-accepted return codes cause `BrokerHandle_Connect()` to return `0`, which makes the caller disconnect the client.

Since unsupported Protocol Level does not set `ack.return_code` to `MQTT_CONNECT_ACK_CODE_REFUSED_PROTO`, it does not trigger this rejection/disconnect path.

### 6. Caller marks the client connected when `BrokerHandle_Connect()` succeeds

File: `wolfMQTT-master/src/mqtt_broker.c:3540`

```c
int c_rc = BrokerHandle_Connect(bc, rc, broker);
if (c_rc <= 0) {
    /* Decode failed or auth rejected, disconnect */
    BrokerSubs_RemoveClient(broker, bc);
    BrokerClient_Remove(broker, bc);
    return 0;
}
bc->connected = 1;
```

If `BrokerHandle_Connect()` sends an accepted CONNACK and returns a positive value, the client is marked connected.

This is the opposite of the standard's required behavior for unsupported Protocol Level:

```text
CONNACK 0x01 + disconnect
```

## Black-Box Test Evidence

A raw socket test was run against:

```text
build/wolfmqtt-connect-test/bin/mqtt_broker
```

The test sent CONNECT packets with Protocol Name `"MQTT"` and different Protocol Level values.

### Test case 1: Protocol Level 0x03

Packet:

```text
10 0d 00 04 4d 51 54 54 03 02 00 3c 00 01 41
```

Meaning:

| Field | Value |
|---|---|
| Protocol Name | `"MQTT"` |
| Protocol Level | `0x03` |
| CleanSession | `1` |
| ClientId | `"A"` |

Expected:

```text
CONNACK return code 0x01, then disconnect
```

Observed:

```json
{"level": 3, "recv_hex": "20020000", "connack_flags": 0, "connack_code": 0, "ping_hex": "d000", "alive": true}
```

The broker returned:

```text
20 02 00 00
```

This means:

```text
CONNACK 0x00 Accepted
```

The broker also responded to `PINGREQ` with `PINGRESP`, showing that the connection remained alive.

### Test case 2: Protocol Level 0x06

Packet:

```text
10 0e 00 04 4d 51 54 54 06 02 00 3c 00 00 01 41
```

Meaning:

| Field | Value |
|---|---|
| Protocol Name | `"MQTT"` |
| Protocol Level | `0x06` |
| CleanSession | `1` |
| ClientId | `"A"` |

Expected:

```text
CONNACK return code 0x01, then disconnect
```

Observed:

```json
{"level": 6, "recv_hex": "2009000006250128012402", "connack_flags": 0, "connack_code": 0, "ping_hex": "d000", "alive": true}
```

The broker again returned an accepted CONNACK and kept the connection alive.

### Control case: Protocol Level 0x04

Packet:

```text
10 0d 00 04 4d 51 54 54 04 02 00 3c 00 01 41
```

Observed:

```json
{"level": 4, "recv_hex": "20020000", "connack_flags": 0, "connack_code": 0, "ping_hex": "d000", "alive": true}
```

This is expected for MQTT 3.1.1 Protocol Level `4`.

The problem is that unsupported levels `3` and `6` behaved the same as supported level `4`.

## Inconsistency Reason

The standard requires a specific rejection path:

```text
unsupported Protocol Level -> CONNACK 0x01 -> disconnect
```

wolfMQTT has the required constants, but the broker CONNECT path does not implement the required decision:

1. `MqttDecode_Connect()` copies `packet.protocol_level` into `mc_connect->protocol_level`.
2. It validates Protocol Name, but not whether the Protocol Level is supported.
3. `BrokerHandle_Connect()` stores `mc.protocol_level` into `bc->protocol_level`.
4. It initializes `ack.return_code` to `MQTT_CONNECT_ACK_CODE_ACCEPTED`.
5. No branch changes the return code to `MQTT_CONNECT_ACK_CODE_REFUSED_PROTO` for unsupported levels.
6. The broker sends `CONNACK 0x00` and marks the client as connected.

This is inconsistent with `[MQTT-3.1.2-2]`.

## Impact

This is a high-risk protocol-conformance issue because it affects the CONNECT handshake, the first protocol decision point.

Potential impacts:

- A client using an unsupported MQTT Protocol Level can be accepted.
- The broker can process later packets under an undefined or mismatched protocol mode.
- In MQTT 5-enabled builds, values greater than `5` can be treated as MQTT 5-style packets because the code uses `>= MQTT_CONNECT_PROTOCOL_LEVEL_5`.
- Fuzzing results may show accepted connections for unsupported protocol versions instead of the required `0x01` refusal.

## Suggested Fix Direction

Add explicit Protocol Level support validation after CONNECT decode and before any normal session processing.

For a build that supports only MQTT 3.1.1:

```c
if (mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_4) {
    ack.flags = 0;
    ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_PROTO;
    goto send_connack;
}
```

For a build that supports both MQTT 3.1.1 and MQTT 5:

```c
if (mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_4 &&
        mc.protocol_level != MQTT_CONNECT_PROTOCOL_LEVEL_5) {
    ack.flags = 0;
    ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_PROTO;
    goto send_connack;
}
```

After sending this non-zero CONNACK, the existing code path:

```c
if (ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
    return 0;
}
```

would cause the caller to remove the client and close the connection.

## Conclusion

The unsupported Protocol Level issue is valid and not satisfied.

The precise conclusion is:

```text
wolfMQTT decodes and stores the client-supplied Protocol Level, but the broker does not reject unsupported Protocol Level values with CONNACK return code 0x01. Unsupported levels can receive CONNACK 0x00 and remain connected, which conflicts with MQTT-3.1.2-2.
```

