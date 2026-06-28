# Empty Topic Filters Are Accepted

## Summary

wolfMQTT accepts MQTT 3.1.1 `SUBSCRIBE` and `UNSUBSCRIBE` packets that contain an empty Topic Filter.

MQTT Topic Filters must be at least one character long. A Topic Filter encoded with a two-byte string length of `0x0000` is therefore malformed. wolfMQTT currently accepts this value during packet decoding because the shared MQTT string decoder checks only that the declared length fits inside the packet buffer; it does not reject zero-length Topic Filters.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `4.7.3 Topic semantic and usage`, clause `[MQTT-4.7.3-1]`.

Original English requirement:

```text
All Topic Names and Topic Filters MUST be at least one character long [MQTT-4.7.3-1].
```

Meaning in this issue:

- A Topic Filter with length `0` is invalid.
- The rule applies to Topic Filters carried by `SUBSCRIBE`.
- The same Topic Filter validity rule also applies when Topic Filters are supplied by `UNSUBSCRIBE`.

## Expected Behavior

The server-side receive path should reject `SUBSCRIBE` and `UNSUBSCRIBE` packets when any Topic Filter has zero length.

| Packet shape | Topic Filter length | Expected result |
|---|---:|---|
| `SUBSCRIBE` with Topic Filter `a` | `1` | Accept |
| `SUBSCRIBE` with empty Topic Filter | `0` | Reject as malformed |
| `UNSUBSCRIBE` with Topic Filter `a` | `1` | Accept |
| `UNSUBSCRIBE` with empty Topic Filter | `0` | Reject as malformed |

This issue is different from an empty `SUBSCRIBE` or `UNSUBSCRIBE` payload. Here, the packet does contain a Topic Filter field, but that field's MQTT string length is zero.

## Code Description

### Shared string decoder accepts zero-length strings

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

This function validates the MQTT string envelope: two-byte length plus enough remaining bytes. It does not reject `str_len == 0`. That is acceptable for fields where MQTT allows an empty UTF-8 string, but it is not sufficient for Topic Names or Topic Filters because Section `4.7.3` imposes a minimum length of one character.

### SUBSCRIBE decoder does not reject empty Topic Filters

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Subscribe()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &topic->topic_filter, NULL,
        (word32)(rx_end - rx_payload));
if (tmp < 0) {
    return tmp;
}
if (rx_payload + tmp > rx_end) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
rx_payload += tmp;
if (rx_payload >= rx_end) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
options = *rx_payload++;
topic->qos = (MqttQoS)(options & 0x03);
subscribe->topic_count++;
```

If the encoded Topic Filter length is `0x0000`, `MqttDecode_String()` returns the two bytes consumed by the length field. The decoder then reads the options byte and increments `topic_count`. There is no check that the decoded Topic Filter length is at least one.

### UNSUBSCRIBE decoder has the same missing validation

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Unsubscribe()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &topic->topic_filter, NULL,
        (word32)(rx_end - rx_payload));
if (tmp < 0) {
    return tmp;
}
if (rx_payload + tmp > rx_end) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
rx_payload += tmp;
unsubscribe->topic_count++;
```

The unsubscribe path similarly increments `topic_count` after string decoding without checking that the Topic Filter is non-empty.

### Broker code trusts the decoded Topic Filter

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Subscribe()`

Relevant code:

```c
rc = MqttDecode_Subscribe(bc->rx_buf, rx_len, &sub);
if (rc < 0) {
    return rc;
}

for (i = 0; i < sub.topic_count && i < MAX_MQTT_TOPICS; i++) {
    const char* f = sub.topics[i].topic_filter;
    word16 flen = 0;
    ...
    if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
            &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        int sub_rc = BrokerSubs_Add(broker, bc, f, flen, topic_qos);
```

Because `MqttDecode_Subscribe()` can accept an empty Topic Filter, the broker can proceed with `flen == 0` and pass that filter to subscription registration.

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Unsubscribe()`

Relevant code:

```c
rc = MqttDecode_Unsubscribe(bc->rx_buf, rx_len, &unsub);
if (rc < 0) {
    return rc;
}

for (i = 0; i < unsub.topic_count && i < MAX_MQTT_TOPICS; i++) {
    const char* f = unsub.topics[i].topic_filter;
    word16 flen = 0;
    if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
            &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        BrokerSubs_Remove(broker, bc, f, flen);
    }
```

The unsubscribe handling path also trusts the decoded filter length.

## Inconsistency

The standard requires every Topic Filter to contain at least one character. wolfMQTT only verifies that the MQTT string length field is internally consistent with the packet size. It does not apply the Topic Filter-specific minimum length rule.

As a result:

- `SUBSCRIBE` with a zero-length Topic Filter is decoded successfully;
- `UNSUBSCRIBE` with a zero-length Topic Filter is decoded successfully;
- broker-side subscription add/remove logic can receive `flen == 0`.

The inconsistency is caused by applying generic MQTT string decoding where Topic Filter-specific validation is required.

## Dynamic Test Evidence

An existing protocol-check reproduction includes an empty `SUBSCRIBE` Topic Filter:

File: `wolfMQTT/201-250/repro_wolfmqtt_201_250_protocol_checks.c`

```c
const byte sub_empty_filter[] = {
    0x82, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00
};
...
failures += expect_reject("SUBSCRIBE empty Topic Filter",
    decode_subscribe(sub_empty_filter, sizeof(sub_empty_filter)));
```

Observed output:

```text
SUBSCRIBE empty Topic Filter                 rc=7 expected=reject observed=accept
```

A focused runtime check for empty Topic Filters produced:

```text
valid SUBSCRIBE filter a             rc=8 observed=accept
empty SUBSCRIBE Topic Filter         rc=7 observed=accept
valid UNSUBSCRIBE filter a           rc=7 observed=accept
empty UNSUBSCRIBE Topic Filter       rc=6 observed=accept
```

The valid non-empty filters are accepted, which is correct. The empty Topic Filters are also accepted, which violates the minimum length requirement.

## Root Cause

The root cause is that `MqttDecode_Subscribe()` and `MqttDecode_Unsubscribe()` use `MqttDecode_String()` without retrieving or validating the decoded string length. Since `MqttDecode_String()` permits `str_len == 0`, the packet-specific Topic Filter validity rule is never enforced.

## Suggested Fix Direction

Decode the Topic Filter length and reject zero-length filters before accepting the topic entry.

One possible direction is:

- call `MqttDecode_String()` with `pstr_len` populated;
- if the decoded Topic Filter length is `0`, return a malformed packet error;
- apply the same check to both `SUBSCRIBE` and `UNSUBSCRIBE` Topic Filter decoding paths.

This check should be separate from the existing empty-payload validation, because a zero-length Topic Filter field and a missing Topic Filter field are different malformed packet shapes.
