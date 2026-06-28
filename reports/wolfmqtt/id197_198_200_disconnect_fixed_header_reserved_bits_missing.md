# DISCONNECT Fixed Header Reserved Bits Are Not Validated

## Summary

wolfMQTT does not validate the fixed-header reserved bits for inbound MQTT 3.1.1 `DISCONNECT` packets.

In MQTT 3.1.1, the low four bits of the `DISCONNECT` fixed header are reserved and must be `0000`. The server must treat any other value as a malformed control packet and close the network connection. wolfMQTT currently checks only the packet type nibble, so a packet such as `E1 00` is accepted as a normal `DISCONNECT` instead of being rejected as a protocol violation.

This problem has two layers:

- the generic fixed-header decoder does not validate packet-specific fixed-header flags;
- the broker dispatch path treats an invalid-flag `DISCONNECT` exactly like a valid one.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant sections:

- `2.2.2 Fixed header`
- `3.14 DISCONNECT - Client is disconnecting`
- `3.14.1 Fixed header`

Original English requirement for packet-specific fixed-header flags from Section `2.2.2`:

```text
Bits 3, 2, 1 and 0 of the fixed header of an MQTT Control Packet are specific to each MQTT Control Packet type.
```

```text
The Server MUST validate that all reserved bits in the fixed header of the Control Packet are set to zero and disconnect the Client if they are not zero.
```

Original English requirement for `DISCONNECT` from Section `3.14.1`:

```text
Bits 3,2,1 and 0 of the fixed header of the DISCONNECT Control Packet are reserved and MUST be set to 0,0,0,0.
```

Detailed English description of the requirement:

For MQTT 3.1.1, a valid `DISCONNECT` packet begins with fixed-header byte `0xE0`. The high nibble `1110` identifies packet type `14`, and the low nibble `0000` is the required reserved-bit pattern for that packet type. A byte such as `0xE1`, `0xE2`, or `0xEF` has the correct packet type nibble but an invalid fixed-header flag pattern. The server must not treat such a packet as a normal `DISCONNECT`; it must recognize the fixed-header violation and close the network connection because the packet is malformed at the protocol level.

## Expected Behavior

For MQTT 3.1.1 `DISCONNECT` receive-side validation:

| First byte | Meaning | Expected result |
|---|---|---|
| `0xE0` | Valid `DISCONNECT`, flags `0000` | Accept |
| `0xE1` | `DISCONNECT`, flags `0001` | Reject as malformed |
| `0xE2` | `DISCONNECT`, flags `0010` | Reject as malformed |
| `0xEF` | `DISCONNECT`, flags `1111` | Reject as malformed |

Checking only that the high nibble equals packet type `14` is insufficient. The low nibble must also be validated against the packet-type-specific fixed-header table.

## Code Evidence

### Generic fixed-header decoder validates only packet type

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_FixedHeader()`

The generic decoder checks only the packet type nibble:

```c
if (MQTT_PACKET_TYPE_GET(header->type_flags) != type) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_TYPE);
}
```

It can optionally extract QoS, retain, and duplicate bits, but it has no parameter for a required fixed-header flag pattern and no per-packet validation table. Therefore it cannot reject `DISCONNECT` packets whose low four bits are not `0000`.

### MQTT 3.1.1 DISCONNECT decoder performs no additional flag validation

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Disconnect()` for MQTT 3.1.1

The MQTT 3.1.1 `DISCONNECT` decoder simply calls the generic fixed-header decoder:

```c
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len, &remain_len,
    MQTT_PACKET_TYPE_DISCONNECT, NULL, NULL, NULL);
```

After that, it does not inspect the fixed-header low nibble at all:

```c
if (disc) {
    /* nothing to decode for v3.1.1 */
}

return header_len + remain_len;
```

As a result, an invalid `DISCONNECT` such as `E1 00` is accepted and returned as a successful decode with length `2`.

### Broker dispatch treats invalid DISCONNECT exactly like valid DISCONNECT

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerClient_Process()`

The broker dispatch switch identifies only the packet type:

```c
byte type = MQTT_PACKET_TYPE_GET(bc->rx_buf[0]);
```

Then it handles `DISCONNECT` as a normal disconnect:

```c
case MQTT_PACKET_TYPE_DISCONNECT:
    BrokerClient_ClearWill(bc); /* normal disconnect */
    if (bc->clean_session) {
        BrokerSubs_RemoveClient(broker, bc);
    }
    else {
        BrokerSubs_OrphanClient(broker, bc);
    }
    BrokerClient_Remove(broker, bc);
    return 0;
```

There is no branch that distinguishes:

- valid `0xE0` fixed header;
- malformed `0xE1` / `0xE2` / `0xEF` fixed headers.

So the broker closes the connection as if the client had sent a well-formed `DISCONNECT`, not because it detected a malformed control packet.

## Reproduction Test

Test file:

```text
wolfMQTT-master/tests/repro_disconnect_invalid_flags_acceptance.c
```

Build and run:

```powershell
cd wolfMQTT-master
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER "-DWOLFMQTT_BROKER_GET_TIME_S()=0" "-DBROKER_SLEEP_MS(ms)=((void)0)" src/mqtt_packet.c src/mqtt_socket.c src/mqtt_client.c tests/repro_disconnect_invalid_flags_acceptance.c -o tests/repro_disconnect_invalid_flags_acceptance.exe
.\tests\repro_disconnect_invalid_flags_acceptance.exe
```

Observed output:

```text
decode valid DISCONNECT        rc=2 expected=accept observed=accept
decode invalid flags E1 00     rc=2 expected=reject observed=accept
broker process valid packet    rc=0 close_count=1 writes=0
broker process invalid flags   rc=0 close_count=1 writes=0
repro verdict: invalid DISCONNECT fixed-header flags were accepted
```

Interpretation:

- `MqttDecode_Disconnect()` accepts `E1 00` and returns success.
- The broker processing path behaves the same for valid and invalid `DISCONNECT`.
- Therefore, invalid fixed-header flags are not surfaced as malformed input.

## Inconsistency

| Standard requirement | wolfMQTT behavior |
|---|---|
| `DISCONNECT` fixed-header low nibble must be `0000` | Any low nibble is accepted if packet type is `DISCONNECT` |
| Server must validate reserved fixed-header bits | Decoder validates only packet type |
| Invalid reserved bits must trigger malformed-packet handling | Invalid `DISCONNECT` is treated like a normal disconnect |
| Protocol violation must be recognized explicitly | Broker path has no invalid-flags branch |

## Root Cause

The implementation conflates two different questions:

```text
Is this packet type DISCONNECT?
```

and:

```text
Is this a well-formed DISCONNECT fixed header?
```

MQTT 3.1.1 requires both checks. wolfMQTT currently performs only the first one.

At the broker level, this leads to a second semantic mismatch:

```text
connection closed because client sent a valid DISCONNECT
```

is treated the same as:

```text
connection closed because client sent a malformed DISCONNECT
```

That loses protocol-violation detection and makes reserved-bit fuzz cases look accepted.

## Suggested Fix Direction

Add packet-type-specific fixed-header validation for `DISCONNECT`, either inside `MqttDecode_FixedHeader()` through a required-flags mechanism, or immediately after decode in `MqttDecode_Disconnect()`.

For MQTT 3.1.1 `DISCONNECT`, the check should be equivalent to:

```c
if ((rx_buf[0] & 0x0F) != 0x00) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

Then ensure the broker dispatch path treats that decode error as malformed input rather than a normal disconnect path.
