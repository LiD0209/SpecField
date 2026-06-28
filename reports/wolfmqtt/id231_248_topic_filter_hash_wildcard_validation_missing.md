# Topic Filter Multi-Level Wildcard Validation Is Missing

## Summary

wolfMQTT accepts malformed MQTT 3.1.1 `SUBSCRIBE` Topic Filters that use the multi-level wildcard `#` in invalid positions.

In MQTT, `#` is a multi-level wildcard. It is valid only when it is either the whole Topic Filter or appears after a topic level separator `/`, and it must be the final character in the Topic Filter. For example, `#`, `sport/#`, and `sport/tennis/#` are valid. Filters such as `a#` and `sport/#/ranking` are malformed.

The wolfMQTT `SUBSCRIBE` decoder currently treats the Topic Filter as a length-prefixed byte string and does not validate this `#` placement rule. Once decoded, the broker registration path can store the malformed Topic Filter as a subscription.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `4.7.1.2 Multi-level wildcard`, clause `[MQTT-4.7.1-2]`.

Original English requirement:

```text
The multi-level wildcard character MUST be specified either on its own or following a topic level separator.
```

```text
In either case it MUST be the last character specified in the Topic Filter [MQTT-4.7.1-2].
```

The same section gives non-normative examples showing that:

```text
sport/tennis/# is valid
sport/tennis# is not valid
sport/tennis/#/ranking is not valid
```

## Expected Behavior

For MQTT 3.1.1 `SUBSCRIBE` packets, the server-side receive path should reject Topic Filters with invalid `#` placement.

| Topic Filter | Expected result | Reason |
|---|---|---|
| `#` | Accept | `#` is the whole Topic Filter |
| `sport/#` | Accept | `#` follows `/` and is the final character |
| `a#` | Reject | `#` does not occupy its own topic level |
| `sport/#/ranking` | Reject | `#` is not the final character |

## Code Description

### Shared string decoder only returns a byte slice

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

This function checks that the declared MQTT string length fits inside the packet buffer. It does not parse Topic Filter syntax and does not inspect whether `#` appears only as a complete final topic level.

### SUBSCRIBE decoder does not validate Topic Filter wildcard syntax

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

After decoding the Topic Filter string, the decoder reads the options byte and increments `topic_count`. There is no check equivalent to:

- if `#` appears, it must be the first character or immediately follow `/`;
- if `#` appears, it must be the final character in the Topic Filter.

Therefore malformed filters such as `a#` and `sport/#/ranking` can be decoded successfully.

### Broker registration can store the decoded invalid filter

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

The broker trusts the decoded `MqttSubscribe` structure. If the decoder accepts a malformed Topic Filter, this path can pass it to `BrokerSubs_Add()` and register it as a subscription.

### Matching code is not sufficient as input validation

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerTopicMatch()`

Relevant code:

```c
if (*f == '#') {
    return (f[1] == '\0');
}
```

This branch only affects matching behavior once a stored filter is compared with a Topic Name. It does not reject malformed filters during `SUBSCRIBE` processing. As a result, invalid filters can still be accepted and stored even if some malformed shapes later fail to match.

## Inconsistency

The standard defines the `#` placement rule as a validity requirement for Topic Filters. wolfMQTT enforces only the MQTT string framing rules during `SUBSCRIBE` decode:

- the two-byte string length must fit in the packet buffer;
- the payload must contain an options byte after the string;
- no validation is performed for `#` as a complete final topic level.

This means wolfMQTT can accept a packet that the MQTT 3.1.1 server receive path should treat as malformed. The inconsistency is not caused by a disagreement in matching semantics; it is caused by missing Topic Filter syntax validation before subscription registration.

## Dynamic Test Evidence

An existing protocol-check reproduction includes an invalid `a#` Topic Filter:

File: `wolfMQTT/201-250/repro_wolfmqtt_201_250_protocol_checks.c`

```c
const byte sub_bad_hash_placement[] = {
    0x82, 0x07, 0x00, 0x01, 0x00, 0x02, 'a', '#', 0x00
};
...
failures += expect_reject("SUBSCRIBE Topic Filter bad # placement",
    decode_subscribe(sub_bad_hash_placement, sizeof(sub_bad_hash_placement)));
```

Build and run command:

```sh
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER \
  wolfMQTT/201-250/repro_wolfmqtt_201_250_protocol_checks.c \
  wolfMQTT-master/src/mqtt_packet.c \
  -o wolfMQTT/201-250/repro_wolfmqtt_201_250_protocol_checks_current.exe

./wolfMQTT/201-250/repro_wolfmqtt_201_250_protocol_checks_current.exe
```

Observed output:

```text
SUBSCRIBE Topic Filter bad # placement       rc=9 expected=reject observed=accept
```

A focused runtime check for `#` placement produced:

```text
valid sport/#                rc=14 observed=accept
invalid a#                   rc=9 observed=accept
invalid sport/#/x            rc=16 observed=accept
```

The valid `sport/#` case is accepted, which is correct. The malformed `a#` and `sport/#/x` cases are also accepted, which demonstrates the missing validation.

## Root Cause

The root cause is that `MqttDecode_Subscribe()` delegates Topic Filter parsing to the generic MQTT string decoder and then proceeds directly to option decoding. There is no dedicated validation function for MQTT Topic Filter wildcard syntax before `topic_count` is incremented and before the broker registers the subscription.

## Suggested Fix Direction

Add Topic Filter validation after `MqttDecode_String()` succeeds and before `subscribe->topic_count++`.

The validation should reject at least:

- any `#` that is not the first character and is not immediately preceded by `/`;
- any `#` that is not the final character in the Topic Filter.

The same validation should be applied consistently anywhere inbound Topic Filters are accepted, including `SUBSCRIBE` and `UNSUBSCRIBE` decoding paths.
