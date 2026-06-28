# CONNECT User Name UTF-8 Validation Is Missing

## Summary

wolfMQTT accepts a MQTT 3.1.1 `CONNECT` packet whose `User Name` field contains ill-formed UTF-8.

The packet shape is structurally valid: `User Name Flag` is set, the payload includes a length-prefixed User Name field, and the declared length fits inside the packet. However, the User Name bytes are not valid UTF-8. wolfMQTT decodes and stores the field anyway, then returns a successful `CONNACK`.

This is a receive-side UTF-8 semantic validation gap. The implementation checks the MQTT string length envelope but not the UTF-8 character data.

## Standard Reference

MQTT Version 3.1.1, Section `1.5.3 UTF-8 encoded strings`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `1.5.3`.

Original English requirement:

```text
The character data in a UTF-8 encoded string MUST be well-formed UTF-8 as defined by the Unicode specification and restated in RFC 3629.
```

Original English requirement:

```text
If a Server or Client receives a Control Packet containing ill-formed UTF-8 it MUST close the Network Connection [MQTT-1.5.3-1].
```

MQTT Version 3.1.1, Section `3.1.3.4 User Name`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.1.3.4`.

Original English requirement:

```text
The User Name MUST be a UTF-8 encoded string as defined in Section 1.5.3 [MQTT-3.1.3-11].
```

Together, these rules require the server to reject a `CONNECT` packet whose User Name field contains malformed UTF-8 bytes.

## Expected Behavior

For MQTT 3.1.1:

| CONNECT payload condition                                 | Expected result                                              |
| --------------------------------------------------------- | ------------------------------------------------------------ |
| `User Name Flag=1`, User Name is well-formed UTF-8      | Accept the User Name field, subject to authentication policy |
| `User Name Flag=1`, User Name contains ill-formed UTF-8 | Close the network connection                                 |

A two-byte length prefix is not enough. The receiver must also validate that the declared bytes form a legal UTF-8 string.

## Code Description

### Shared MQTT string decoder only checks length

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_String()`

Relevant code:

```c
int MqttDecode_String(byte *buf, const char **pstr, word16 *pstr_len, word32 buf_len)
{
    int len;
    word16 str_len;
    len = MqttDecode_Num(buf, &str_len, buf_len);
    if (len < 0) {
        return len;
    }
    if ((word32)str_len > buf_len - (word32)len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    buf += len;
    if (pstr_len) {
        *pstr_len = str_len;
    }
    if (pstr) {
        *pstr = (char*)buf;
    }
    return len + str_len;
}
```

This function verifies that the two-byte MQTT string length fits in the available buffer. It does not decode UTF-8 code points, reject overlong encodings, reject invalid continuation bytes, or reject surrogate encodings.

### CONNECT decoder uses the shared decoder for User Name

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

The decoder reads the User Name only when `User Name Flag` is set, and it checks packet bounds. It does not validate that the decoded bytes are well-formed UTF-8.

### Broker stores the accepted User Name

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
if (mc.username) {
    word16 ulen = 0;
    if (MqttDecode_Num((byte*)mc.username - MQTT_DATA_LEN_SIZE,
            &ulen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        BROKER_STORE_STR_SENSITIVE(bc->username, mc.username, ulen,
            BROKER_MAX_USERNAME_LEN);
    }
}
```

The broker recovers the length and stores the User Name bytes. There is no UTF-8 semantic validation before the successful `CONNACK` path.

## Runtime Reproduction

A broker-level reproducer is available at:

`wolfMQTT/251-300/repro_connect_username_invalid_utf8.c`

The test sends a raw MQTT 3.1.1 `CONNECT` packet with:

| Field           | Value                                                |
| --------------- | ---------------------------------------------------- |
| Protocol Name   | `MQTT`                                             |
| Protocol Level  | `4`                                                |
| Connect Flags   | `0x82` (`Clean Session=1`, `User Name Flag=1`) |
| ClientId        | `cid`                                              |
| User Name bytes | `C0 AF`                                            |

`C0 AF` is an overlong UTF-8 byte sequence and is ill-formed under RFC 3629.

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\251-300\repro_connect_username_invalid_utf8.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\251-300\repro_connect_username_invalid_utf8.exe
wolfMQTT\251-300\repro_connect_username_invalid_utf8.exe
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

`20 02 00 00` is a successful MQTT 3.1.1 `CONNACK`. The broker accepted the connection even though the User Name field contained ill-formed UTF-8.

## Inconsistency Reason

The implementation validates only the structural envelope of the User Name field:

```text
two-byte length exists
declared length fits in packet
bytes are copied/stored
```

The standard requires semantic validation of the character data:

```text
the bytes must be well-formed UTF-8
if not, the network connection must be closed
```

Because `MqttDecode_String()` is a generic length decoder and `MqttDecode_Connect()` does not add User Name-specific UTF-8 validation, malformed UTF-8 can pass through to the broker.

## Impact

This is a protocol input-validation issue.

Potential impact:

| Effect                   | Description                                                                                                  |
| ------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Protocol non-compliance  | A malformed MQTT 3.1.1 `CONNECT` packet is accepted instead of causing connection close.                   |
| Authentication ambiguity | User Name bytes that are not valid UTF-8 can reach authentication logic.                                     |
| Interoperability risk    | Clients and brokers that enforce UTF-8 strictly may behave differently from wolfMQTT.                        |
| Robustness risk          | Higher layers may assume User Name is valid UTF-8 even though the broker accepted arbitrary malformed bytes. |

## Suggested Fix Direction

Add UTF-8 semantic validation for MQTT UTF-8 encoded strings after length decoding and before accepting the field.

For `CONNECT` User Name specifically, `MqttDecode_Connect()` should reject the packet if the decoded User Name bytes are not well-formed UTF-8:

```c
if (!MqttValidate_Utf8(username, username_len)) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
```

The same validator should be shared by all MQTT UTF-8 string fields, including ClientId, Will Topic, Topic Name, Topic Filter, User Name, and Password.
