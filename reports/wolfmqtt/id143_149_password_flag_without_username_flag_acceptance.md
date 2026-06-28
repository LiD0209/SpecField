# Password Flag Without User Name Flag Is Accepted

## Summary

wolfMQTT's CONNECT decoder accepts a malformed MQTT 3.1.1 packet where `Password Flag` is `1` while `User Name Flag` is `0`.

This is inconsistent with MQTT 3.1.1 because the protocol explicitly requires `Password Flag` to be `0` whenever `User Name Flag` is `0`. wolfMQTT enforces this relationship when it encodes its own CONNECT packets, but the broker-side decoder does not enforce the same relationship when parsing inbound CONNECT packets.

## Standard Reference

MQTT 3.1.1, Section `3.1.2.8 User Name Flag` and Section `3.1.2.9 Password Flag`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Sections `3.1.2.8` and `3.1.2.9`.

Original English requirement:

```text
If the User Name Flag is set to 0, a user name MUST NOT be present in the payload [MQTT-3.1.2-18].
```

Original English requirement:

```text
If the Password Flag is set to 1, a password MUST be present in the payload [MQTT-3.1.2-21].
```

Original English linkage requirement:

```text
If the User Name Flag is set to 0, the Password Flag MUST be set to 0 [MQTT-3.1.2-22].
```

This makes the following flag combination invalid:

```text
User Name Flag = 0
Password Flag  = 1
```

The packet is invalid before payload parsing details matter, because the CONNECT flags themselves violate the required relationship.

## Expected Behavior

For MQTT 3.1.1 CONNECT flags:

| User Name Flag | Password Flag | Expected result |
|---:|---:|---|
| 0 | 0 | Valid: no user name and no password |
| 1 | 0 | Valid: user name without password |
| 1 | 1 | Valid: user name and password |
| 0 | 1 | Invalid: password without user name |

The decoder should reject the last case as malformed.

## Code Description

### Sending side enforces the linkage rule

File: `wolfMQTT-master/src/mqtt_packet.c:774`

```c
/* [MQTT-3.1.2-22]: If the User Name Flag is set to 0, the Password Flag
 * MUST be set to 0 */
if (mc_connect->password != NULL && mc_connect->username == NULL) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
}
```

This prevents wolfMQTT from encoding a CONNECT packet with a password but no user name.

The encoder then derives flags from the fields that are present:

File: `wolfMQTT-master/src/mqtt_packet.c:882`

```c
if (mc_connect->username) {
    packet.flags |= MQTT_CONNECT_FLAG_USERNAME;
}
if (mc_connect->password) {
    packet.flags |= MQTT_CONNECT_FLAG_PASSWORD;
}
```

The encoder also writes the fields in the expected CONNECT payload order:

File: `wolfMQTT-master/src/mqtt_packet.c:937`

```c
if (mc_connect->username) {
    tx_payload += MqttEncode_String(tx_payload, mc_connect->username);
}
if (mc_connect->password) {
    tx_payload += MqttEncode_String(tx_payload, mc_connect->password);
}
```

So the outbound path has a strong construction rule: a password cannot be generated without a user name.

### Receiving side reads fields by flag, but does not reject the invalid flag pair

File: `wolfMQTT-master/src/mqtt_packet.c:1118`

```c
if (packet.flags & MQTT_CONNECT_FLAG_USERNAME) {
    tmp = MqttDecode_String(rx_payload, &mc_connect->username, NULL,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
    if (tmp < 0) {
        return tmp;
    }
    if ((rx_payload - rx_buf) + tmp > header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    rx_payload += tmp;
}
```

File: `wolfMQTT-master/src/mqtt_packet.c:1130`

```c
if (packet.flags & MQTT_CONNECT_FLAG_PASSWORD) {
    tmp = MqttDecode_String(rx_payload, &mc_connect->password, NULL,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
    if (tmp < 0) {
        return tmp;
    }
    if ((rx_payload - rx_buf) + tmp > header_len + remain_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    rx_payload += tmp;
}
```

The decoder correctly uses `User Name Flag` to decide whether to parse the user name field, and it correctly uses `Password Flag` to decide whether to parse the password field.

However, there is no explicit check equivalent to:

```c
if ((packet.flags & MQTT_CONNECT_FLAG_PASSWORD) &&
    !(packet.flags & MQTT_CONNECT_FLAG_USERNAME)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

At the end, the decoder returns success after the conditional field parsing:

File: `wolfMQTT-master/src/mqtt_packet.c:1142`

```c
(void)rx_payload;

/* Return total length of packet */
return header_len + remain_len;
```

This means an inbound CONNECT packet can set `Password Flag=1` while leaving `User Name Flag=0`, and the decoder can still accept it.

## Reproduction

A small reproducer was added at:

`wolfMQTT-master/tests/repro_password_flag_without_username_flag.c`

The malformed packet uses:

- Fixed header type: `CONNECT`
- Protocol name: `MQTT`
- Protocol level: `4`
- Connect flags: `0x42`
- Meaning of `0x42`: `Clean Session=1`, `Password Flag=1`, `User Name Flag=0`
- Payload: ClientId `cid`, then a password field `secret`

Compile and run from `wolfMQTT-master`:

```powershell
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c tests/repro_password_flag_without_username_flag.c -o tests/repro_password_flag_without_username_flag.exe
.\tests\repro_password_flag_without_username_flag.exe
```

Observed output:

```text
valid no credentials
  decode rc: 17
  accepted: yes
  username: (null)
  password: (null)
password flag 1 with username flag 0
  decode rc: 25
  accepted: yes
  username: (null)
  password: secret
valid username and password
  decode rc: 31
  accepted: yes
  username: user
  password: secret
repro verdict: issue reproduced: invalid flag combination was accepted
```

The malformed packet is accepted with `decode rc: 25`, even though `Password Flag=1` and `User Name Flag=0` is forbidden by MQTT 3.1.1.

## Inconsistency Reason

The implementation has asymmetric enforcement:

- Outbound CONNECT encoding enforces the relationship by rejecting `password != NULL && username == NULL`.
- Inbound CONNECT decoding does not enforce the corresponding flag relationship.

The decoder treats the two flags as independent field-presence indicators:

```text
if User Name Flag is set, read user name
if Password Flag is set, read password
```

But the standard requires a cross-field invariant:

```text
Password Flag may be 1 only when User Name Flag is also 1
```

Because that invariant is missing from the receive path, an invalid CONNECT packet can be accepted and decoded as containing a password with no user name.

## Suggested Fix Direction

`MqttDecode_Connect()` should reject the invalid flag pair immediately after decoding the CONNECT flags:

```c
if ((packet.flags & MQTT_CONNECT_FLAG_PASSWORD) &&
    !(packet.flags & MQTT_CONNECT_FLAG_USERNAME)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would make the receive path enforce the same MQTT 3.1.1 relationship already enforced by the send path.
