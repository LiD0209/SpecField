# Topic Filter Single-Level Wildcard Validation Is Missing

## Summary

wolfMQTT accepts malformed MQTT 3.1.1 `SUBSCRIBE` and `UNSUBSCRIBE` Topic Filters where the single-level wildcard `+` is embedded inside a topic level.

In MQTT, `+` is a single-level wildcard. It can appear at any topic level, but it must occupy the entire level. For example, `+`, `sport/+`, and `sport/+/player1` are valid. Filters such as `a+b` and `sport+` are malformed because `+` is mixed with other characters in the same level.

The wolfMQTT decoders currently treat Topic Filters as length-prefixed byte strings and do not validate this `+` placement rule. Once a malformed Topic Filter is decoded, broker-side subscription add/remove logic can process it as if it were valid.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `4.7.1.3 Single-level wildcard`, clause `[MQTT-4.7.1-3]`.

Original English requirement:

```text
The single-level wildcard can be used at any level in the Topic Filter, including first and last levels.
```

```text
Where it is used it MUST occupy an entire level of the filter [MQTT-4.7.1-3].
```

The same section gives examples showing that:

```text
+ is valid
+/tennis/# is valid
sport+ is not valid
sport/+/player1 is valid
```

## Expected Behavior

For MQTT 3.1.1 `SUBSCRIBE` and `UNSUBSCRIBE` packets, the server-side receive path should reject Topic Filters where `+` is not the whole topic level.

| Topic Filter | Expected result | Reason |
|---|---|---|
| `+` | Accept | `+` is the whole Topic Filter and the whole level |
| `sport/+` | Accept | `+` occupies the final level |
| `sport/+/player1` | Accept | `+` occupies the middle level |
| `a+b` | Reject | `+` is embedded inside a level |
| `sport+` | Reject | `+` is embedded inside a level |
| `sport+/player1` | Reject | `+` is not the whole first level |

## Code Description

### Shared string decoder only validates the MQTT string envelope

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_String()`

Relevant code:

```c
len = MqttDecode_Num(buf, &str_len, buf_len);
if (len < 0) {
    return len;
}
if ((word32)str_len > buf_len - (word32)len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
buf += len;
if (pstr) {
    *pstr = (char*)buf;
}
return len + str_len;
```

This function checks that the two-byte MQTT string length fits inside the available packet buffer. It does not parse Topic Filter syntax and does not inspect whether `+` appears as a complete topic level.

### SUBSCRIBE decoder does not validate single-level wildcard placement

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

After decoding the Topic Filter string, the decoder reads the options byte and increments `topic_count`. There is no check that each `+` is either:

- the first character of the Topic Filter or immediately follows `/`; and
- the last character of the Topic Filter or immediately precedes `/`.

Therefore malformed filters such as `a+b` and `sport+` can be decoded successfully.

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

The unsubscribe path also accepts the decoded Topic Filter without checking `+` placement.

### Broker registration trusts the decoded filter

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

If `MqttDecode_Subscribe()` accepts a malformed Topic Filter, the broker can pass it to `BrokerSubs_Add()` and register it as a subscription.

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

The unsubscribe handling path similarly trusts the decoded Topic Filter.

### Matching code is not input validation

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerTopicMatch()`

Relevant code:

```c
if (*f == '+') {
    while (*t && *t != '/') {
        t++;
    }
    f++;
}
```

This branch performs matching-time wildcard handling. It does not validate whether the stored filter was syntactically valid when received. If an invalid filter has already been stored, this logic can still apply wildcard behavior to a `+` embedded inside a topic level.

## Inconsistency

The standard defines `+` placement as a Topic Filter validity rule: when `+` appears, it must occupy an entire topic level. wolfMQTT currently applies only generic MQTT string decoding during `SUBSCRIBE` and `UNSUBSCRIBE` processing.

As a result:

- `SUBSCRIBE` with `a+b` can be decoded successfully;
- `SUBSCRIBE` with `sport+` can be decoded successfully;
- `UNSUBSCRIBE` with `a+b` can be decoded successfully;
- broker-side add/remove logic can process these malformed filters.

The inconsistency is caused by missing Topic Filter syntax validation before the decoded filter is accepted by the broker.

## Dynamic Test Evidence

An existing protocol-check reproduction includes an invalid `a+b` Topic Filter:

File: `wolfMQTT/201-250/repro_wolfmqtt_201_250_protocol_checks.c`

```c
const byte sub_bad_plus_placement[] = {
    0x82, 0x08, 0x00, 0x01, 0x00, 0x03, 'a', '+', 'b', 0x00
};
...
failures += expect_reject("SUBSCRIBE Topic Filter bad + placement",
    decode_subscribe(sub_bad_plus_placement, sizeof(sub_bad_plus_placement)));
```

Observed output:

```text
SUBSCRIBE Topic Filter bad + placement       rc=10 expected=reject observed=accept
```

A focused runtime check for `+` placement produced:

```text
valid SUBSCRIBE sport/+/r              rc=16 observed=accept
invalid SUBSCRIBE a+b                  rc=10 observed=accept
invalid SUBSCRIBE sport+               rc=12 observed=accept
valid UNSUBSCRIBE sport/+/r            rc=15 observed=accept
invalid UNSUBSCRIBE a+b                rc=9 observed=accept
```

The valid filters are accepted, which is correct. The malformed filters are also accepted, which violates the single-level wildcard placement requirement.

## Root Cause

The root cause is that `MqttDecode_Subscribe()` and `MqttDecode_Unsubscribe()` use the generic MQTT string decoder and do not run Topic Filter-specific wildcard validation before accepting the entry.

## Suggested Fix Direction

Add Topic Filter validation after `MqttDecode_String()` succeeds and before incrementing `topic_count`.

The validation should reject any `+` where:

- the previous character exists and is not `/`; or
- the next character exists and is not `/`.

The same validation should be applied consistently to all inbound Topic Filters, including `SUBSCRIBE` and `UNSUBSCRIBE` decoding paths.
