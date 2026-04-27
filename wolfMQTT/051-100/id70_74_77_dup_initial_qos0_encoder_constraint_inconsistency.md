# ID70/71/72/73/74/77: PUBLISH DUP Initial-Send and QoS0 Constraint Is Not Enforced by the Generic Encoder

## Summary

Affected requirement IDs: 70, 71, 72, 73, 74, 77.

The wolfMQTT broker forwarding paths usually set `out_pub.duplicate = 0`, so the main broker delivery path is not the primary source of the inconsistency. The inconsistency is at the generic packet encoder boundary: `MqttEncode_Publish()` accepts `publish->duplicate` from the caller and encodes it directly into the PUBLISH fixed header, even when `publish->qos == MQTT_QOS_0`.

This means the library API can encode a QoS0 PUBLISH with DUP set to 1. MQTT 3.1.1 explicitly forbids that combination for all QoS0 messages, and it also describes the first transmission of QoS1 and QoS2 PUBLISH packets as using DUP=0.

Classification: partial satisfaction.

## MQTT 3.1.1 Requirement

Source document: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`

Relevant sections:

- Section 3.3.1.1, PUBLISH fixed header, DUP flag.
- Section 4.3.1, QoS 0 delivery protocol.
- Section 4.3.2, QoS 1 delivery protocol.
- Section 4.3.3, QoS 2 delivery protocol.

Short normative excerpts:

```text
"DUP=0 for all QoS 0 messages"
"QoS=0, DUP=0"
"QoS=1, DUP=0"
"QoS=2, DUP=0"
```

Detailed English description of the standard requirement:

```text
In MQTT 3.1.1, the DUP flag in a PUBLISH packet describes whether this packet is the first attempt to send that MQTT PUBLISH packet or a possible re-delivery of an earlier attempt. A sender must set DUP to 1 when it attempts to re-deliver a PUBLISH packet. Conversely, when the sender is sending a new application message for the first time, the protocol flow descriptions for QoS1 and QoS2 both specify DUP=0 on the initial PUBLISH.

For QoS0, the rule is stricter and unconditional: every QoS0 PUBLISH message must have DUP set to 0. QoS0 has no acknowledgement and no retry in the protocol flow, so a QoS0 PUBLISH with DUP=1 is not a valid MQTT 3.1.1 encoding.

The server forwarding rule is also relevant: when a server forwards an incoming PUBLISH to subscribers, it must not propagate the incoming packet's DUP flag. The outgoing DUP value must be determined independently, based only on whether the outgoing PUBLISH is a retransmission.
```

## Code Evidence: Broker Paths Usually Clear DUP

The broker retained-message delivery path clears DUP before encoding:

```c
XMEMSET(&out_pub, 0, sizeof(out_pub));
out_pub.topic_name = rm->topic;
out_pub.qos = MQTT_QOS_0;
out_pub.retain = 1;
out_pub.duplicate = 0;
enc_rc = MqttEncode_Publish(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &out_pub, 0);
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:2343`, `wolfMQTT-master/src/mqtt_broker.c:2347`, `wolfMQTT-master/src/mqtt_broker.c:2353`.

The will-message / offline-style publish delivery path also clears DUP:

```c
out_pub.qos = eff_qos;
out_pub.retain = 0;
out_pub.duplicate = 0;
enc_rc = MqttEncode_Publish(sub->client->tx_buf, BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:2489`, `wolfMQTT-master/src/mqtt_broker.c:2491`, `wolfMQTT-master/src/mqtt_broker.c:2500`.

The normal broker forwarding path also clears DUP:

```c
out_pub.qos = eff_qos;
out_pub.retain = 0;
out_pub.duplicate = 0;
rc = MqttEncode_Publish(sub->client->tx_buf, BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:3300`, `wolfMQTT-master/src/mqtt_broker.c:3305`, `wolfMQTT-master/src/mqtt_broker.c:3315`.

These paths support the "partial satisfaction" part of the finding: common broker-generated outgoing PUBLISH packets are constructed with DUP=0.

## Code Evidence: Generic Encoder Trusts Caller-Supplied DUP

The public PUBLISH encoder accepts a `MqttPublish` object:

```c
int MqttEncode_Publish(byte *tx_buf, int tx_buf_len, MqttPublish *publish,
                        byte use_cb)
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:1292`.

It checks whether a packet identifier is present when QoS is greater than 0:

```c
if (publish->qos > MQTT_QOS_0) {
    if (publish->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }
    variable_len += MQTT_DATA_LEN_SIZE;
}
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:1308`.

There is no corresponding check that rejects or clears `publish->duplicate` when `publish->qos == MQTT_QOS_0`.

The encoder then passes `publish->duplicate` directly to fixed-header encoding:

```c
header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len,
    variable_len + payload_len, publish->type,
    publish->retain, publish->qos, publish->duplicate);
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:1341`.

The fixed-header encoder sets the DUP bit whenever the `duplicate` argument is non-zero:

```c
if (duplicate) {
    header->type_flags |=
        MQTT_PACKET_FLAGS_SET(MQTT_PACKET_FLAG_DUPLICATE);
}
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:169`.

Therefore, the API boundary permits this caller-controlled state:

```c
pub.qos = MQTT_QOS_0;
pub.duplicate = 1;
```

That state should not be encodable under MQTT 3.1.1, because all QoS0 PUBLISH messages must have DUP=0.

## Minimal Reproduction

The local probe used this setup:

```c
MqttPublish pub;
memset(&pub, 0, sizeof(pub));
pub.topic_name = "a";
pub.qos = MQTT_QOS_0;
pub.retain = 0;
pub.duplicate = 1;
pub.buffer = (byte*)"x";
pub.total_len = 1;
int rc = MqttEncode_Publish(buf, sizeof(buf), &pub, 0);
```

Observed output:

```text
rc=6
first_byte=0x38
380400016178
```

The first byte `0x38` is:

```text
0x30 PUBLISH fixed-header type
+0x08 DUP flag
=0x38
```

The encoded packet is therefore a QoS0 PUBLISH with DUP=1. That is the forbidden combination.

## Why This Is an Inconsistency

The inconsistency is not that every wolfMQTT broker PUBLISH is wrong. The broker's main outgoing PUBLISH construction generally sets `duplicate = 0`.

The inconsistency is that the generic encoder is a public library API and does not enforce the MQTT 3.1.1 invariant at the point where the wire bytes are produced. A caller can pass `qos = MQTT_QOS_0` and `duplicate = 1`; the encoder will produce a wire packet with DUP set.

For IDs 70, 73, 74, and 77, this directly violates the QoS0 hard constraint because the encoder permits QoS0 + DUP=1.

For IDs 71 and 72, the same design weakness applies to initial QoS1 and QoS2 sends. The broker path normally initializes DUP to 0, but `MqttEncode_Publish()` itself has no concept of "first send" versus "re-delivery"; it simply encodes the caller-provided flag. Therefore, first-send DUP=0 is achieved by caller convention in common paths, not by a uniform library-level constraint.

## Classification Rationale

Recommended category:

```text
DUP initial-send / QoS0 hard constraint incomplete
```

Recommended status:

```text
partial satisfaction
```

Reason:

wolfMQTT satisfies the requirement on common broker forwarding paths by explicitly assigning `out_pub.duplicate = 0`. However, the generic `MqttEncode_Publish()` API does not reject or normalize invalid DUP values. It can encode a standards-forbidden QoS0 PUBLISH with DUP=1, so the implementation does not provide a complete library-level guarantee for the DUP initial-send and QoS0 invariants.
