# Password Flag 0 Extra Payload Is Accepted

## Summary

wolfMQTT's CONNECT decoder accepts a malformed MQTT 3.1.1 packet where the `Password Flag` is `0`, but the CONNECT payload still contains a length-prefixed password field after the user name.

This is inconsistent with MQTT 3.1.1 because the flag says that no password is present, while the payload still carries password-shaped bytes. The decoder follows the flag and skips password parsing, but it does not verify that the payload has been fully consumed.

## Standard Reference

MQTT 3.1.1, Section `3.1.2.9 Password Flag`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.2.9`.

Original English requirement excerpt:

```text
a password MUST NOT be present in the payload
```

This is the requirement for `Password Flag = 0` in `[MQTT-3.1.2-20]`.

Related rules in the same section:

- If `Password Flag = 1`, the password field is required in the payload.
- If `User Name Flag = 0`, `Password Flag` must also be `0`.

MQTT 3.1.1, Section `3.1.3 Payload`, also defines the CONNECT payload field order:

- `Client Identifier`
- `Will Topic`
- `Will Message`
- `User Name`
- `Password`

The important consequence is that a password field after the user name is meaningful only when `Password Flag = 1`. When `Password Flag = 0`, those bytes should make the CONNECT packet invalid instead of being silently ignored.

## Expected Behavior

For MQTT 3.1.1 CONNECT decoding:

| Connect Flags | Payload content | Expected result |
|---|---|---|
| `User Name Flag=1`, `Password Flag=0` | ClientId + User Name | Accept |
| `User Name Flag=1`, `Password Flag=1` | ClientId + User Name + Password | Accept |
| `User Name Flag=1`, `Password Flag=0` | ClientId + User Name + Password | Reject as malformed |

The third case is the problematic one. The payload contains a password field even though the flag says no password exists.

## Code Description

### Sending side enforces the normal construction rule

File: `wolfMQTT-master/src/mqtt_packet.c:774`

```c
/* [MQTT-3.1.2-22]: If the User Name Flag is set to 0, the Password Flag
 * MUST be set to 0 */
if (mc_connect->password != NULL && mc_connect->username == NULL) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
}
```

The encoder rejects the invalid combination where a password is supplied without a user name. It also derives the CONNECT flags from the fields that are present.

File: `wolfMQTT-master/src/mqtt_packet.c:882`

```c
if (mc_connect->username) {
    packet.flags |= MQTT_CONNECT_FLAG_USERNAME;
}
if (mc_connect->password) {
    packet.flags |= MQTT_CONNECT_FLAG_PASSWORD;
}
```

File: `wolfMQTT-master/src/mqtt_packet.c:937`

```c
if (mc_connect->username) {
    tx_payload += MqttEncode_String(tx_payload, mc_connect->username);
}
if (mc_connect->password) {
    tx_payload += MqttEncode_String(tx_payload, mc_connect->password);
}
```

This means wolfMQTT-generated CONNECT packets normally keep the flags and payload consistent.

### Receiving side only conditionally reads fields

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

The decoder reads the password only when `MQTT_CONNECT_FLAG_PASSWORD` is set. If the flag is clear, it skips password decoding.

File: `wolfMQTT-master/src/mqtt_packet.c:1142`

```c
(void)rx_payload;

/* Return total length of packet */
return header_len + remain_len;
```

At the end of decoding, `rx_payload` is discarded. There is no final check equivalent to:

```c
if (rx_payload != rx_buf + header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

Because that final consumption check is missing, extra payload bytes can remain after the decoded fields and the packet can still be accepted.

## Reproduction

A small reproducer was added at:

`wolfMQTT-master/tests/repro_password_flag0_extra_payload.c`

The malformed packet uses:

- Fixed header type: `CONNECT`
- Protocol name: `MQTT`
- Protocol level: `4`
- Connect flags: `0x82`
- Meaning of `0x82`: `Clean Session=1`, `User Name Flag=1`, `Password Flag=0`
- Payload: ClientId `cid`, User Name `user`, then an extra password field `secret`

Compile and run from `wolfMQTT-master`:

```powershell
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c tests/repro_password_flag0_extra_payload.c -o tests/repro_password_flag0_extra_payload.exe
.\tests\repro_password_flag0_extra_payload.exe
```

Observed output:

```text
valid username only
  decode rc: 23
  accepted: yes
  username: user
  password: (null)
password flag 0 with extra password payload
  decode rc: 31
  accepted: yes
  username: user
  password: (null)
valid username and password
  decode rc: 31
  accepted: yes
  username: user
  password: secret
repro verdict: issue reproduced: malformed packet was accepted
```

The malformed packet is accepted with `decode rc: 31`, even though `Password Flag=0` and password bytes are present in the payload.

## Inconsistency Reason

The implementation correctly uses `Password Flag` to decide whether to parse the password field. However, that is not enough to enforce the MQTT 3.1.1 packet format.

The missing piece is a payload-consumption invariant:

```text
after decoding all fields indicated by CONNECT flags,
the decoder must have consumed exactly the CONNECT Remaining Length
```

Without this invariant, the receiver treats a malformed packet as if it were a valid username-only CONNECT packet plus ignored trailing bytes.

So the inconsistency is:

- Standard: `Password Flag=0` means no password field is present in the payload.
- Code behavior: `Password Flag=0` means the decoder does not read the password field.
- Gap: the decoder does not reject remaining payload bytes that look like an extra password field.

## Suggested Fix Direction

After the optional fields are decoded, `MqttDecode_Connect()` should verify that `rx_payload` has reached the end of the CONNECT packet body:

```c
if ((rx_payload - rx_buf) != header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would reject `Password Flag=0` packets that carry extra password payload, and it would also strengthen CONNECT payload consistency for other optional fields controlled by flags.
