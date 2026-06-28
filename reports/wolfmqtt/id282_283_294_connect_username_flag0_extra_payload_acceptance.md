# User Name Flag 0 Extra Payload Is Accepted

## Summary

wolfMQTT's CONNECT decoder can accept a malformed MQTT 3.1.1 packet where `User Name Flag` is `0`, but the CONNECT payload still contains an extra User Name field after the ClientId.

The decoder conditionally parses the User Name only when `User Name Flag` is set. However, after skipping the User Name branch, it does not verify that the whole CONNECT payload has been consumed. As a result, a trailing username-like field can be silently ignored, and the broker can still return a successful `CONNACK`.

## Standard Reference

MQTT Version 3.1.1, Section `3.1.2.8 User Name Flag`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.2.8`.

Original English requirement:

```text
If the User Name Flag is set to 0, a user name MUST NOT be present in the payload [MQTT-3.1.2-18].
```

MQTT Version 3.1.1, Section `3.1.3 Payload`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.3`.

Original English description:

```text
The Payload of the CONNECT Packet contains one or more length-prefixed fields, whose presence is determined by the flags in the variable header.
```

Together, these rules mean that a User Name field is allowed only when the corresponding flag says it is present. If `User Name Flag=0`, a trailing User Name field is not valid CONNECT payload.

## Expected Behavior

For MQTT 3.1.1 CONNECT packets:

| User Name Flag | Payload after ClientId  | Expected result                 |
| -------------: | ----------------------- | ------------------------------- |
|          `0` | no User Name field      | Accept this part of the payload |
|          `1` | valid User Name field   | Accept this part of the payload |
|          `0` | User Name field present | Reject as malformed             |

The receiver should also verify that after parsing the fields allowed by the flags, no unexpected payload bytes remain.

## Code Description

### Encoder sets User Name Flag only when username exists

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_Connect()`

Relevant code:

```c
if (mc_connect->username) {
    packet.flags |= MQTT_CONNECT_FLAG_USERNAME;
}
```

The encoder constructs normal outbound packets consistently: when a username is present, it sets `User Name Flag`.

It also writes the User Name field only when `mc_connect->username` is present:

```c
if (mc_connect->username) {
    tx_payload += MqttEncode_String(tx_payload, mc_connect->username);
}
```

So wolfMQTT's own construction path normally avoids creating `User Name Flag=0` with a User Name field.

### Decoder parses User Name only when the flag is set

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Connect()`

Relevant code:

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

This branch is correct as far as conditional parsing goes: when `User Name Flag=1`, it attempts to read the User Name field.

The missing piece is the corresponding rejection when `User Name Flag=0` but extra payload remains.

### Decoder does not check that the payload was fully consumed

At the end of `MqttDecode_Connect()`, the code returns success without verifying that `rx_payload` reached the end of the CONNECT packet:

```c
(void)rx_payload;

/* Return total length of packet */
return header_len + remain_len;
```

There is no check equivalent to:

```c
if ((rx_payload - rx_buf) != header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

Because of this, unexpected trailing bytes can remain after the fields selected by the CONNECT flags have been parsed.

## Runtime Reproduction

A broker-level reproducer is available at:

`wolfMQTT/251-300/repro_connect_username_flag0_extra_payload.c`

The malformed CONNECT packet uses:

| Field               | Value                                                                    |
| ------------------- | ------------------------------------------------------------------------ |
| Protocol Name       | `MQTT`                                                                 |
| Protocol Level      | `4`                                                                    |
| Connect Flags       | `0x02`                                                                 |
| Meaning of `0x02` | `Clean Session=1`, `User Name Flag=0`, `Password Flag=0`           |
| Payload             | ClientId `cid`, then an extra length-prefixed User Name field `user` |

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\251-300\repro_connect_username_flag0_extra_payload.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\251-300\repro_connect_username_flag0_extra_payload.exe
wolfMQTT\251-300\repro_connect_username_flag0_extra_payload.exe
```

Observed output:

```text
MqttBroker_Start rc=0
accept step rc=0 output_len=4
connect step rc=-101 output_len=4
connack bytes: 20 02 00 00
connack return_code=0
accepted=yes
```

`20 02 00 00` is a successful MQTT 3.1.1 `CONNACK`. The broker accepted the malformed CONNECT packet even though `User Name Flag=0` and the payload contained an extra User Name field.

## Inconsistency Reason

The implementation follows the flags for conditional field parsing:

```text
if User Name Flag is set:
  read User Name
else:
  do not read User Name
```

But the standard also requires the inverse consistency rule:

```text
if User Name Flag is not set:
  User Name must not be present in the payload
```

That inverse rule requires either:

- rejecting unexpected trailing payload bytes after the last allowed field; or
- explicitly validating that the payload fields exactly match the CONNECT flags.

wolfMQTT does neither. It returns the total packet length even when `rx_payload` has not consumed all bytes described by the Remaining Length. This lets flag/payload mismatches pass as successful CONNECT packets.

## Impact

This is a protocol input-validation issue.

Potential impact:

| Effect                  | Description                                                                                        |
| ----------------------- | -------------------------------------------------------------------------------------------------- |
| Protocol non-compliance | A malformed CONNECT packet is accepted instead of rejected.                                        |
| Parser ambiguity        | The packet contains bytes that look like a User Name field, but the flag says no User Name exists. |
| Interoperability risk   | Strict MQTT peers can reject packets that wolfMQTT accepts.                                        |
| Fuzzing blind spot      | Extra payload bytes can be hidden behind unset CONNECT flags without surfacing as malformed data.  |

## Suggested Fix Direction

After all flag-selected CONNECT payload fields are parsed, `MqttDecode_Connect()` should verify full payload consumption:

```c
if ((rx_payload - rx_buf) != header_len + remain_len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

This would reject:

| CONNECT condition                                          | Expected rejection reason                         |
| ---------------------------------------------------------- | ------------------------------------------------- |
| `User Name Flag=0`, trailing User Name field present     | unexpected payload bytes                          |
| `Password Flag=0`, trailing Password field present       | unexpected payload bytes                          |
| Any extra bytes after the last valid CONNECT payload field | payload does not match Remaining Length semantics |

The same validation area should be combined with explicit CONNECT flag cross-checks, such as rejecting `Password Flag=1` when `User Name Flag=0`.
