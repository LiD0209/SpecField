# CONNECT Flags Cross-Constraint Violations Are Accepted

## Summary

wolfMQTT's CONNECT decoder accepts several malformed MQTT 3.1.1 CONNECT packets whose Connect Flags byte violates protocol cross-constraints.

The client-side encoder normally constructs legal Connect Flags, but the broker-side decoder does not apply equivalent validation when parsing inbound CONNECT packets. As a result, malformed flag combinations can be accepted and decoded instead of being rejected as protocol errors.

## Standard Reference

MQTT 3.1.1, Section `3.1.2.3 Connect Flags`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.2.3`.

The Connect Flags byte is defined as:

| Bit | Name |
|---:|---|
| 7 | User Name Flag |
| 6 | Password Flag |
| 5 | Will Retain |
| 4-3 | Will QoS |
| 2 | Will Flag |
| 1 | Clean Session |
| 0 | Reserved |

Original English requirement for the reserved bit:

```text
The Server MUST validate that the reserved flag in the CONNECT Control Packet is set to zero and disconnect the Client if it is not zero [MQTT-3.1.2-3].
```

MQTT 3.1.1, Section `3.1.2.6 Will Flag` and Section `3.1.2.7 Will QoS`:

```text
If the Will Flag is set to 0, then the Will QoS MUST be set to 0 (0x00) [MQTT-3.1.2-13].
```

MQTT 3.1.1, Section `3.1.2.6 Will Flag` and Section `3.1.2.5 Will Retain`:

```text
If the Will Flag is set to 0, then the Will Retain Flag MUST be set to 0 [MQTT-3.1.2-15].
```

MQTT 3.1.1, Section `3.1.2.8 User Name Flag` and Section `3.1.2.9 Password Flag`:

```text
If the User Name Flag is set to 0, the Password Flag MUST be set to 0 [MQTT-3.1.2-22].
```

These requirements mean that Connect Flags are not independent booleans. Some bits constrain other bits.

## Expected Behavior

For MQTT 3.1.1 CONNECT decoding:

| Connect Flags condition | Expected result |
|---|---|
| Reserved bit is `1` | Reject and disconnect |
| `Will Flag=0`, `Will QoS!=0` | Reject |
| `Will Flag=0`, `Will Retain=1` | Reject |
| `User Name Flag=0`, `Password Flag=1` | Reject |
| Legal combinations only | Continue payload decoding |

The malformed cases should fail before normal CONNECT processing continues.

## Code Description

### Flag definitions are available

File: `wolfMQTT-master/wolfmqtt/mqtt_packet.h:329`

```c
enum MqttConnectFlags {
    MQTT_CONNECT_FLAG_RESERVED = 0x01,
    MQTT_CONNECT_FLAG_CLEAN_SESSION = 0x02, /* Old v3.1.1 name */
    MQTT_CONNECT_FLAG_CLEAN_START   = 0x02,
    MQTT_CONNECT_FLAG_WILL_FLAG = 0x04,
    MQTT_CONNECT_FLAG_WILL_QOS_SHIFT = 3,
    MQTT_CONNECT_FLAG_WILL_QOS_MASK = 0x18,
    MQTT_CONNECT_FLAG_WILL_RETAIN = 0x20,
    MQTT_CONNECT_FLAG_PASSWORD = 0x40,
    MQTT_CONNECT_FLAG_USERNAME = 0x80
};
```

The implementation has named masks for all relevant bits, including the reserved bit and the cross-constrained flags.

### Sending side constructs mostly legal flag combinations

File: `wolfMQTT-master/src/mqtt_packet.c:774`

```c
/* [MQTT-3.1.2-22]: If the User Name Flag is set to 0, the Password Flag
 * MUST be set to 0 */
if (mc_connect->password != NULL && mc_connect->username == NULL) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
}
```

This prevents wolfMQTT from encoding a password without a user name.

File: `wolfMQTT-master/src/mqtt_packet.c:872`

```c
if (mc_connect->enable_lwt) {
    packet.flags |= MQTT_CONNECT_FLAG_WILL_FLAG;

    if (mc_connect->lwt_msg->qos) {
        packet.flags |= MQTT_CONNECT_FLAG_SET_QOS(mc_connect->lwt_msg->qos);
    }
    if (mc_connect->lwt_msg->retain) {
        packet.flags |= MQTT_CONNECT_FLAG_WILL_RETAIN;
    }
}
```

This means the encoder only sets Will QoS and Will Retain through the Last Will branch. Normal wolfMQTT-generated packets therefore avoid `Will Flag=0` with Will QoS or Will Retain set.

File: `wolfMQTT-master/src/mqtt_packet.c:882`

```c
if (mc_connect->username) {
    packet.flags |= MQTT_CONNECT_FLAG_USERNAME;
}
if (mc_connect->password) {
    packet.flags |= MQTT_CONNECT_FLAG_PASSWORD;
}
```

The outbound construction path is comparatively strict.

### Receiving side does not validate the same cross-constraints

File: `wolfMQTT-master/src/mqtt_packet.c:997`

```c
mc_connect->protocol_level = packet.protocol_level;
mc_connect->clean_session =
    (packet.flags & MQTT_CONNECT_FLAG_CLEAN_SESSION) ? 1 : 0;
mc_connect->enable_lwt =
    (packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) ? 1 : 0;
mc_connect->username = NULL;
mc_connect->password = NULL;
```

The decoder extracts `Clean Session` and `Will Flag`, but there is no immediate validation of:

- `MQTT_CONNECT_FLAG_RESERVED`
- `Will Flag=0` with nonzero `MQTT_CONNECT_FLAG_WILL_QOS_MASK`
- `Will Flag=0` with `MQTT_CONNECT_FLAG_WILL_RETAIN`
- `Password Flag=1` with `User Name Flag=0`

File: `wolfMQTT-master/src/mqtt_packet.c:1048`

```c
if (mc_connect->enable_lwt) {
    if (mc_connect->lwt_msg == NULL) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }

    mc_connect->lwt_msg->qos =
        (MqttQoS)MQTT_CONNECT_FLAG_GET_QOS(packet.flags);
    mc_connect->lwt_msg->retain =
        (packet.flags & MQTT_CONNECT_FLAG_WILL_RETAIN) ? 1 : 0;
```

Will QoS and Will Retain are only read when `Will Flag=1`. If those bits are set while `Will Flag=0`, they are ignored rather than rejected.

File: `wolfMQTT-master/src/mqtt_packet.c:1118`

```c
if (packet.flags & MQTT_CONNECT_FLAG_USERNAME) {
    tmp = MqttDecode_String(rx_payload, &mc_connect->username, NULL,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

File: `wolfMQTT-master/src/mqtt_packet.c:1130`

```c
if (packet.flags & MQTT_CONNECT_FLAG_PASSWORD) {
    tmp = MqttDecode_String(rx_payload, &mc_connect->password, NULL,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

User name and password are parsed by separate flag checks. The decoder does not first reject the forbidden pair `Password Flag=1` and `User Name Flag=0`.

File: `wolfMQTT-master/src/mqtt_packet.c:1142`

```c
(void)rx_payload;

/* Return total length of packet */
return header_len + remain_len;
```

The decoder can return success after conditional field parsing, even if the Connect Flags byte itself was invalid.

## Reproduction

A small reproducer was added at:

`wolfMQTT-master/tests/repro_connect_flags_cross_constraints.c`

Compile and run from `wolfMQTT-master`:

```powershell
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c tests/repro_connect_flags_cross_constraints.c -o tests/repro_connect_flags_cross_constraints.exe
.\tests\repro_connect_flags_cross_constraints.exe
```

Observed output:

```text
valid clean-session only
  flags: 0x02
  decode rc: 17
  accepted: yes
  enable_lwt: 0
  username present: no
  password present: no
invalid reserved bit set
  flags: 0x03
  decode rc: 17
  accepted: yes
  enable_lwt: 0
  username present: no
  password present: no
invalid will qos set while will flag is 0
  flags: 0x0A
  decode rc: 17
  accepted: yes
  enable_lwt: 0
  username present: no
  password present: no
invalid will retain set while will flag is 0
  flags: 0x22
  decode rc: 17
  accepted: yes
  enable_lwt: 0
  username present: no
  password present: no
invalid password flag set while username flag is 0
  flags: 0x42
  decode rc: 25
  accepted: yes
  enable_lwt: 0
  username present: no
  password present: yes
repro verdict: issue reproduced: invalid connect flag combinations were accepted
```

The malformed flag combinations are accepted:

| Flags | Violation |
|---:|---|
| `0x03` | Reserved bit is set |
| `0x0A` | `Will Flag=0`, but Will QoS is nonzero |
| `0x22` | `Will Flag=0`, but Will Retain is set |
| `0x42` | `User Name Flag=0`, but Password Flag is set |

## Inconsistency Reason

The implementation validates some construction-time relationships on the sending path, but the receiving path treats Connect Flags mostly as independent field selectors.

That creates this mismatch:

- Standard: the Server must validate Connect Flags cross-constraints and reject invalid combinations.
- Sending code: wolfMQTT generally avoids producing invalid combinations.
- Receiving code: `MqttDecode_Connect()` does not reject several invalid combinations from the network.

The core missing invariant is:

```text
after reading the CONNECT flags byte, validate the full flag combination
before decoding optional payload fields
```

Without that invariant, invalid bits can either be ignored or used independently, allowing malformed CONNECT packets to pass as accepted packets.

## Suggested Fix Direction

`MqttDecode_Connect()` should validate the Connect Flags byte immediately after copying the CONNECT variable header and before payload parsing:

```c
if (packet.flags & MQTT_CONNECT_FLAG_RESERVED) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}

if (!(packet.flags & MQTT_CONNECT_FLAG_WILL_FLAG) &&
    (packet.flags & (MQTT_CONNECT_FLAG_WILL_QOS_MASK |
                     MQTT_CONNECT_FLAG_WILL_RETAIN))) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}

if ((packet.flags & MQTT_CONNECT_FLAG_PASSWORD) &&
    !(packet.flags & MQTT_CONNECT_FLAG_USERNAME)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The same validation area should also reject reserved Will QoS value `3` when `Will Flag=1`, because the Will QoS field only allows `0`, `1`, or `2`.
