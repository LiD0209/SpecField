# UTF-8 Well-Formed Validation Is Missing

## Summary

This document shows that wolfMQTT treats MQTT UTF-8 strings mainly as length-prefixed byte slices and does not perform full well-formed UTF-8 validation. Invalid byte sequences, surrogate code point encodings, and ClientId/topic string violations can be accepted instead of causing the MQTT 3.1.1 required network-connection close.

## English Standard Text

The relevant MQTT 3.1.1 rule is in Section `1.5.3 UTF-8 encoded strings`, clause `[MQTT-1.5.3-1]`.

Original English text with context:

```text
Text fields in the Control Packets described later are encoded as UTF-8 strings.

The character data in a UTF-8 encoded string MUST be well-formed UTF-8
as defined by the Unicode specification and restated in RFC 3629.

In particular this data MUST NOT include encodings of code points between
U+D800 and U+DFFF.

If a Server or Client receives a Control Packet containing ill-formed UTF-8
it MUST close the Network Connection [MQTT-1.5.3-1].
```

Meaning in this issue:

- The rule applies to MQTT Control Packet text fields, not just to one specific packet.
- The receiver must verify UTF-8 syntax, not merely preserve the original bytes.
- Surrogate code points `U+D800` through `U+DFFF` are explicitly forbidden.
- If such invalid data is received, the required behavior is to close the network connection.

The ClientId-specific rule is in the CONNECT payload section, clause `[MQTT-3.1.3-4]`.

Original English text:

```text
The ClientId MUST be a UTF-8 encoded string as defined in Section 1.5.3
[MQTT-3.1.3-4].
```

Therefore, the generic UTF-8 validation rule applies to `ClientId`, topic names, topic filters, Will Topic, User Name, and other MQTT UTF-8 string fields.

## Code Description

### 1. The shared string decoder only checks length

File: `wolfMQTT-master/src/mqtt_packet.c:338`

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

This function decodes the two-byte MQTT string length and verifies that the declared length stays within the available packet buffer. It then returns a pointer to the raw bytes. It does not:

- decode UTF-8 code points;
- reject malformed byte sequences such as overlong encodings;
- reject surrogate code point encodings such as `ED A0 80` (`U+D800`).
- reject other RFC3629-invalid byte patterns, such as illegal continuation bytes, truncated multi-byte sequences, or invalid leading bytes.

### 2. CONNECT uses the shared decoder for ClientId

File: `wolfMQTT-master/src/mqtt_packet.c:1038`

Function: `MqttDecode_Connect()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &mc_connect->client_id, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
if (tmp < 0) {
    return tmp;
}
```

Because `MqttDecode_Connect()` delegates `ClientId` parsing to `MqttDecode_String()`, an invalid UTF-8 ClientId can pass through as long as its length field is valid.

### 3. Topic strings use the same decoder

File: `wolfMQTT-master/src/mqtt_packet.c:1434`

Examples:

```c
variable_len = MqttDecode_String(rx_payload, &publish->topic_name,
    &publish->topic_name_len, (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

```c
tmp = MqttDecode_String(rx_payload, &topic->topic_filter, NULL,
        (word32)(rx_end - rx_payload));
```

The same length-only behavior applies to PUBLISH Topic Name, SUBSCRIBE Topic Filter, and UNSUBSCRIBE Topic Filter.

### 4. Broker stores accepted strings after decode

File: `wolfMQTT-master/src/mqtt_broker.c:2694`

Function: `BrokerHandle_Connect()`

Relevant code:

```c
rc = MqttDecode_Connect(bc->rx_buf, rx_len, &mc);
if (rc < 0) {
    return rc;
}
...
BROKER_STORE_STR(bc->client_id, mc.client_id, id_len,
    BROKER_MAX_CLIENT_ID_LEN);
```

Once the decoder accepts the string, the broker stores it. There is no later UTF-8 validation before accepting the CONNECT.

## Dynamic Test Evidence

The repro script sends MQTT 3.1.1 packets containing invalid UTF-8:

- `connect_clientid_overlong`: ClientId bytes `C0 AF`
- `connect_clientid_surrogate`: ClientId bytes `ED A0 80`
- `subscribe_topic_overlong`: topic bytes `74 2F C0 AF`
- `subscribe_topic_surrogate`: topic bytes `74 2F ED A0 80`

Observed results:

```text
connect_clientid_overlong -> CONNACK 20020000, return_code=0, PINGRESP d000
connect_clientid_surrogate -> CONNACK 20020000, return_code=0, PINGRESP d000
subscribe_topic_overlong -> SUBACK 9003000700, return_codes=[0], PINGRESP d000
subscribe_topic_surrogate -> SUBACK 9003000700, return_codes=[0], PINGRESP d000
```

The broker accepts the packets and keeps the connection alive.

## Inconsistency Reason

The standard requires semantic UTF-8 validation for MQTT UTF-8 strings. The implementation treats MQTT strings as length-prefixed byte slices. This is enough for bounds safety, but not enough for protocol compliance.

Because `ClientId` and topic fields share the same length-only decoder, the missing check appears both as a general UTF-8 validation issue and as a ClientId-specific violation.

## Conclusion


The UTF-8 well-formedness issues should be grouped together as one high-risk root cause: the receive path lacks MQTT 3.1.1 UTF-8 well-formed validation, including RFC3629 format checks and surrogate-code-point rejection.
