# Wildcard Subscription Rejection Is Missing When Wildcards Are Disabled

## Summary

wolfMQTT can be built with broker wildcard matching disabled, but in that configuration it still accepts `SUBSCRIBE` requests whose Topic Filters contain wildcard characters.

MQTT 3.1.1 allows a Server to choose not to support wildcard subscriptions. However, if the Server chooses not to support them, it must reject any subscription request whose Topic Filter contains a wildcard character. In wolfMQTT, disabling broker wildcards changes the matching function to exact string matching, but it does not add a `SUBSCRIBE` input check that rejects Topic Filters containing `#` or `+`.

This is a conditional protocol inconsistency: the default wildcard-enabled build can accept wildcard Topic Filters, but the wildcard-disabled build should reject them.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `3.8.3 Payload`, clause `[MQTT-3.8.3-2]`.

Original English requirement:

```text
The Server MAY choose to reject any Topic Filter that contains a wildcard character.
```

```text
If it does so it MUST reject any Subscription request whose filter contains a wildcard character [MQTT-3.8.3-2].
```

Meaning in this issue:

- Supporting wildcard subscriptions is optional.
- If wildcard subscriptions are supported, wildcard Topic Filters such as `sport/#` and `sport/+` can be accepted.
- If wildcard subscriptions are not supported, the Server must reject subscriptions containing `#` or `+`.

## Expected Behavior

When broker wildcard support is disabled, the `SUBSCRIBE` receive path should reject wildcard Topic Filters.

| Broker wildcard support | Topic Filter | Expected result |
|---|---|---|
| Enabled | `sport/#` | Accept if otherwise valid |
| Enabled | `sport/+/rank` | Accept if otherwise valid |
| Disabled | `sports` | Accept if otherwise valid |
| Disabled | `sport/#` | Reject |
| Disabled | `sport/+/rank` | Reject |

## Code Description

### Build option disables wildcard matching

File: `wolfMQTT-master/CMakeLists.txt`

Relevant code:

```cmake
add_option(WOLFMQTT_BROKER_WILDCARDS
           "Enable broker wildcard topic matching"
           "yes" "yes;no")
if (NOT WOLFMQTT_BROKER_WILDCARDS)
    list(APPEND WOLFMQTT_DEFINITIONS "-DWOLFMQTT_BROKER_NO_WILDCARDS")
endif()
```

When `WOLFMQTT_BROKER_WILDCARDS` is set to `no`, the build defines `WOLFMQTT_BROKER_NO_WILDCARDS`.

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h`

Relevant code:

```c
#ifndef WOLFMQTT_BROKER_NO_WILDCARDS
    #define WOLFMQTT_BROKER_WILDCARDS
#endif
```

This means defining `WOLFMQTT_BROKER_NO_WILDCARDS` prevents `WOLFMQTT_BROKER_WILDCARDS` from being enabled.

### Wildcard-disabled matching becomes exact matching

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerTopicMatch()`

Relevant code:

```c
#ifdef WOLFMQTT_BROKER_WILDCARDS
static int BrokerTopicMatch(const char* filter, const char* topic)
{
    ...
}
#else
/* Exact match only when wildcards are disabled */
static int BrokerTopicMatch(const char* filter, const char* topic)
{
    if (filter == NULL || topic == NULL) {
        return 0;
    }
    return (XSTRCMP(filter, topic) == 0);
}
#endif /* WOLFMQTT_BROKER_WILDCARDS */
```

This changes only later topic matching behavior. It does not reject wildcard Topic Filters when the subscription is received.

### SUBSCRIBE handling still registers decoded filters

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
    MqttQoS topic_qos = sub.topics[i].qos;
    MqttQoS granted_qos;
    ...
    if (f && MqttDecode_Num((byte*)f - MQTT_DATA_LEN_SIZE,
            &flen, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        int sub_rc = BrokerSubs_Add(broker, bc, f, flen, topic_qos);
```

After `MqttDecode_Subscribe()` succeeds, the broker registers each decoded Topic Filter. There is no conditional check such as:

```c
#ifndef WOLFMQTT_BROKER_WILDCARDS
if (filter contains '#' or '+') reject the subscription
#endif
```

### Decoder also does not know about the wildcard-disabled policy

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Subscribe()`

Relevant code:

```c
tmp = MqttDecode_String(rx_payload, &topic->topic_filter, NULL,
        (word32)(rx_end - rx_payload));
if (tmp < 0) {
    return tmp;
}
...
options = *rx_payload++;
topic->qos = (MqttQoS)(options & 0x03);
subscribe->topic_count++;
```

The decoder extracts the Topic Filter and requested QoS. It does not reject wildcard characters, and it does not branch on whether the broker was compiled with wildcard matching enabled.

## Inconsistency

The standard creates a conditional rule:

```text
if the Server chooses not to support wildcard subscriptions:
  reject subscriptions whose Topic Filter contains # or +
```

wolfMQTT implements only part of that choice:

```text
if wildcards are disabled:
  perform exact matching instead of wildcard matching
```

It does not implement the required receive-side rejection. Therefore, in a wildcard-disabled build, wildcard Topic Filters can still be accepted and stored even though they will no longer behave as wildcard subscriptions during matching.

## Dynamic Test Evidence

A focused decode test was compiled with wildcard support disabled:

```sh
gcc -x c - -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER \
  -DWOLFMQTT_BROKER_NO_WILDCARDS \
  wolfMQTT-master/src/mqtt_packet.c \
  -o wolfMQTT/201-250/repro_no_wildcards_subscribe_current.exe
```

The test decodes:

- a plain Topic Filter `sports`;
- a wildcard Topic Filter `sport/#`;
- a wildcard Topic Filter `sport/+/r`.

Observed output:

```text
compile_config wildcards=disabled
plain SUBSCRIBE sports               rc=13 observed=accept
wildcard SUBSCRIBE sport/#           rc=14 observed=accept
wildcard SUBSCRIBE sport/+/r         rc=16 observed=accept
```

The plain Topic Filter is accepted, which is expected. The wildcard Topic Filters are also accepted even though the build configuration has disabled wildcard support.

## Root Cause

The root cause is that `WOLFMQTT_BROKER_NO_WILDCARDS` changes matching behavior but does not introduce a corresponding `SUBSCRIBE` validation rule. The implementation has no policy check between decoding a Topic Filter and registering it as a subscription.

## Suggested Fix Direction

When `WOLFMQTT_BROKER_WILDCARDS` is not defined, validate inbound `SUBSCRIBE` Topic Filters before registration.

At minimum:

- scan each decoded Topic Filter for `#` or `+`;
- reject the subscription request or mark that subscription as failed;
- avoid storing wildcard Topic Filters in wildcard-disabled builds.

The check should be placed before `BrokerSubs_Add()` so the broker does not persist a Topic Filter that the selected feature policy does not support.
