# Retained Message QoS Is Not Stored

## Summary

wolfMQTT stores retained message topic and payload data, but it does not store the QoS of the retained Application Message.

As a result, a retained `PUBLISH` received at QoS 1 or QoS 2 is later delivered to new subscribers as a retained QoS 0 `PUBLISH`. The payload is retained, but the retained message's QoS semantics are lost.

## Standard Reference

MQTT Version 3.1.1, Section `3.3.1.3 RETAIN`:

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html), Section `3.3.1.3`.

Original English requirement:

```text
If the RETAIN flag is set to 1, in a PUBLISH Packet sent by a Client to a Server, the Server MUST store the Application Message and its QoS, so that it can be delivered to future subscribers whose subscriptions match its topic name [MQTT-3.3.1-5].
```

This requirement is not limited to storing the payload bytes. The retained Application Message includes its QoS, and that QoS must remain available for future retained delivery.

## Expected Behavior

When a broker receives a retained message:

```text
Client -> Broker: PUBLISH retain=1, QoS=1, topic=retain/qos, payload=msg
Broker stores: topic, payload, and QoS=1
```

When a later subscriber matches that topic:

```text
Client -> Broker: SUBSCRIBE retain/qos, requested QoS=1
Broker -> Client: retained PUBLISH retain=1, QoS=1
```

The delivered QoS should be derived from the stored retained message QoS and the subscription's maximum QoS. A retained QoS 1 message delivered to a QoS 1 subscription should not be downgraded to QoS 0 simply because it was retained.

## Code Description

### Retained Store Has No QoS Field

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h`

Relevant structure:

```c
typedef struct BrokerRetainedMsg {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    topic[BROKER_MAX_TOPIC_LEN];
    byte    payload[BROKER_MAX_PAYLOAD_LEN];
#else
    char*   topic;
    byte*   payload;
    struct BrokerRetainedMsg* next;
#endif
    word32  payload_len;
    WOLFMQTT_BROKER_TIME_T store_time;
    word32  expiry_sec;
} BrokerRetainedMsg;
```

The retained message record stores topic, payload, payload length, store time, and expiry, but it has no `qos` field.

### Retained Store Function Does Not Receive QoS

File: `wolfMQTT-master/src/mqtt_broker.c`

Relevant function signature:

```c
static int BrokerRetained_Store(MqttBroker* broker, const char* topic,
    const byte* payload, word32 payload_len, word32 expiry_sec)
```

The function has no `MqttQoS qos` parameter, so it cannot store the QoS of the inbound retained `PUBLISH`.

The normal inbound `PUBLISH` path calls it like this:

```c
int ret_rc = BrokerRetained_Store(broker, topic, payload,
    pub.total_len, expiry);
```

The call passes topic, payload, payload length, and expiry only. It does not pass `pub.qos`.

### Retained Delivery Is Forced to QoS 0

File: `wolfMQTT-master/src/mqtt_broker.c`

Relevant retained delivery code:

```c
static void BrokerRetained_DeliverToClient(MqttBroker* broker,
    BrokerClient* bc, const char* filter, MqttQoS sub_qos)
{
    WOLFMQTT_BROKER_TIME_T now;
    (void)sub_qos; /* retained always delivered at QoS 0 in this broker */
```

The subscription QoS is explicitly ignored.

When encoding the retained `PUBLISH`, the broker forces the outgoing QoS to 0:

```c
out_pub.topic_name = rm->topic;
out_pub.qos = MQTT_QOS_0;
out_pub.retain = 1;
out_pub.duplicate = 0;
out_pub.buffer = (rm->payload_len > 0) ? rm->payload : NULL;
out_pub.total_len = rm->payload_len;
```

The same QoS 0 assignment exists in both static-memory and dynamic-memory retained delivery paths.

## Runtime Reproduction

A broker-level reproducer is available at:

`wolfMQTT/201-250/repro_retained_qos_lost.c`

The reproducer uses wolfMQTT's broker logic with custom network callbacks. It performs this sequence:

| Step | Action                                                                      |
| ---- | --------------------------------------------------------------------------- |
| 1    | Publisher connects.                                                         |
| 2    | Publisher sends `PUBLISH retain=1, QoS=1, topic=retain/qos, payload=msg`. |
| 3    | Broker stores the retained payload and returns `PUBACK`.                  |
| 4    | Subscriber connects.                                                        |
| 5    | Subscriber sends `SUBSCRIBE retain/qos` with requested QoS 1.             |
| 6    | Broker sends the retained message to the subscriber.                        |

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=0' '-DBROKER_SLEEP_MS(ms)=((void)0)' wolfMQTT\201-250\repro_retained_qos_lost.c wolfMQTT-master\src\mqtt_broker.c wolfMQTT-master\src\mqtt_packet.c wolfMQTT-master\src\mqtt_client.c wolfMQTT-master\src\mqtt_socket.c -o wolfMQTT\201-250\repro_retained_qos_lost.exe
wolfMQTT\201-250\repro_retained_qos_lost.exe
```

Observed output:

```text
MqttBroker_Start rc=0
publisher connect step rc=0
publisher retained publish step rc=0
publisher output: 20 02 00 00 40 02 00 07
subscriber connect step rc=0
subscriber subscribe step rc=0
subscriber output: 20 02 00 00 31 0F 00 0A 72 65 74 61 69 6E 2F 71 6F 73 6D 73 67 90 03 00 01 01
retained publish fixed_header=0x31 qos=0 retain=1
```

The publisher's retained message used QoS 1, and the subscriber requested QoS 1. The retained message delivered to the subscriber has fixed header `0x31`, which means:

| Field       |       Value |
| ----------- | ----------: |
| Packet type | `PUBLISH` |
| DUP         |       `0` |
| QoS         |       `0` |
| RETAIN      |       `1` |

This confirms that wolfMQTT delivers the retained message as QoS 0.

## Inconsistency Reason

The implementation stores only part of the retained Application Message:

```text
stored: topic, payload, payload length, expiry
missing: QoS
```

Because the retained store has no QoS field, the retained delivery path cannot calculate the outgoing QoS from:

```text
min(stored retained message QoS, subscription maximum QoS)
```

Instead, it uses a fixed behavior:

```text
retained delivery QoS = 0
```

That is inconsistent with the MQTT 3.1.1 retained message requirement to store the Application Message and its QoS.

## Impact

This is a protocol semantic issue rather than a memory-safety issue.

Potential impact:

| Effect                    | Description                                                                                                 |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| QoS downgrade             | Retained QoS 1 or QoS 2 messages are delivered to future subscribers as QoS 0.                              |
| Lost delivery guarantee   | A subscriber that requested QoS 1 may receive the retained message without QoS 1 acknowledgement semantics. |
| Incomplete retained state | The broker cannot faithfully reconstruct retained messages because it discarded their QoS at store time.    |
| Interoperability risk     | Clients expecting MQTT retained QoS behavior may observe weaker delivery semantics than requested.          |

## Suggested Fix Direction

The retained message model should store QoS with the retained Application Message:

```c
typedef struct BrokerRetainedMsg {
    ...
    MqttQoS qos;
} BrokerRetainedMsg;
```

`BrokerRetained_Store()` should accept and save the inbound retained `PUBLISH` QoS:

```c
BrokerRetained_Store(broker, topic, payload, pub.total_len, pub.qos, expiry);
```

Retained delivery should then compute effective QoS from the stored retained QoS and the subscriber's requested maximum QoS:

```c
out_pub.qos = (rm->qos < sub_qos) ? rm->qos : sub_qos;
```

Regression tests should include:

| Stored retained QoS | Subscription QoS | Expected retained delivery QoS |
| ------------------: | ---------------: | -----------------------------: |
|                   0 |                0 |                              0 |
|                   0 |                1 |                              0 |
|                   1 |                0 |                              0 |
|                   1 |                1 |                              1 |
|                   2 |                1 |                              1 |
|                   2 |                2 |                              2 |
