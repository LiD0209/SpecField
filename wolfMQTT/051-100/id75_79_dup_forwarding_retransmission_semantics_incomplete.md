# ID75/79: Outgoing PUBLISH DUP Is Independent from Incoming DUP, but Retransmission-Based DUP Semantics Are Incomplete

## Summary

Affected requirement IDs: 75, 79.

wolfMQTT's broker forwarding path does not propagate the incoming PUBLISH packet's DUP flag. It decodes the incoming PUBLISH into `pub`, creates a fresh outgoing `out_pub`, and explicitly sets `out_pub.duplicate = 0` before forwarding to subscribers.

That satisfies the first part of the MQTT 3.1.1 rule: the outgoing DUP value is independent from the incoming DUP value.

However, the standard also says the outgoing DUP value must be determined solely by whether the outgoing PUBLISH packet is a retransmission. wolfMQTT does not appear to maintain an outgoing PUBLISH retransmission state machine or an inflight PUBLISH store that can later resend the same PUBLISH with DUP=1. Therefore the implementation is incomplete for the full retransmission-based DUP semantics.

Classification: partial satisfaction.

## MQTT 3.1.1 Requirement

Source document: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`

Relevant sections:

- Section 3.3.1.1, PUBLISH fixed header, DUP flag.
- Section 4.4, Message delivery retry.

Short normative excerpts:

```text
"The value of the DUP flag from an incoming PUBLISH packet is not propagated..."
"...MUST be determined solely by whether the outgoing PUBLISH packet is a retransmission"
"The DUP flag MUST be set to 1 ... when it attempts to re-deliver a PUBLISH Packet"
```

Detailed English description of the standard requirement:

```text
In MQTT 3.1.1, when a Server receives a PUBLISH packet and sends an outgoing PUBLISH packet to subscribers, the Server must not copy the incoming packet's DUP flag into the outgoing packet. The outgoing DUP flag is independent from the incoming DUP flag.

The outgoing DUP flag must be decided only by the retransmission status of the outgoing PUBLISH packet. If the outgoing PUBLISH is the first delivery attempt, DUP is 0. If the Client or Server attempts to re-deliver that PUBLISH packet, DUP must be 1.

Section 4.4 further clarifies the required retry circumstance: when a Client reconnects with CleanSession set to 0, both sides must re-send unacknowledged QoS>0 PUBLISH packets and PUBREL packets using their original Packet Identifiers. This is the only circumstance where MQTT 3.1.1 requires message redelivery.
```

## Code Evidence: Incoming DUP Is Decoded

The broker receives and decodes an incoming PUBLISH packet:

```c
XMEMSET(&pub, 0, sizeof(pub));
rc = MqttDecode_Publish(bc->rx_buf, rx_len, &pub);
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:3202`, `wolfMQTT-master/src/mqtt_broker.c:3207`.

`MqttDecode_Publish()` obtains the incoming DUP value through `MqttDecode_FixedHeader()`:

```c
header_len = MqttDecode_FixedHeader(rx_buf, rx_buf_len,
    &remain_len, publish->type, &publish->qos,
    &publish->retain, &publish->duplicate);
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:1425`.

So the incoming DUP value exists in `pub.duplicate`, but this value is not reused for forwarding.

## Code Evidence: Broker Forwarding Does Not Propagate Incoming DUP

When the broker fans out an incoming PUBLISH to matching subscribers, it creates a new `MqttPublish` object:

```c
MqttPublish out_pub;
MqttQoS eff_qos;
XMEMSET(&out_pub, 0, sizeof(out_pub));
out_pub.topic_name = topic;
eff_qos = (pub.qos < sub->qos) ? pub.qos : sub->qos;
out_pub.qos = eff_qos;
if (eff_qos >= MQTT_QOS_1) {
    out_pub.packet_id = BrokerNextPacketId(broker);
}
out_pub.retain = 0;
out_pub.duplicate = 0;
out_pub.buffer = payload;
out_pub.total_len = pub.total_len;
rc = MqttEncode_Publish(sub->client->tx_buf,
        BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:3295`, `wolfMQTT-master/src/mqtt_broker.c:3297`, `wolfMQTT-master/src/mqtt_broker.c:3299`, `wolfMQTT-master/src/mqtt_broker.c:3305`, `wolfMQTT-master/src/mqtt_broker.c:3315`.

This is good evidence for partial satisfaction:

- The outgoing PUBLISH is constructed separately from the incoming `pub`.
- The broker recomputes effective QoS.
- The broker assigns a new outgoing Packet Identifier for QoS1/QoS2 forwarding.
- The broker explicitly sets `out_pub.duplicate = 0`.

Therefore, an incoming PUBLISH with DUP=1 does not cause the forwarded PUBLISH to inherit DUP=1.

## Code Evidence: Generic Encoder Only Encodes Caller-Supplied DUP

The generic PUBLISH encoder does not decide whether a packet is a retransmission. It simply encodes the `duplicate` value supplied by the caller:

```c
header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len,
    variable_len + payload_len, publish->type,
    publish->retain, publish->qos, publish->duplicate);
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:1341`.

The fixed-header encoder then writes the DUP bit if the caller-provided argument is non-zero:

```c
if (duplicate) {
    header->type_flags |=
        MQTT_PACKET_FLAGS_SET(MQTT_PACKET_FLAG_DUPLICATE);
}
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:169`.

This means the encoder has no built-in state for "first delivery attempt" versus "retransmission". It cannot enforce the full MQTT rule by itself.

## Code Evidence: Missing Retransmission State for Outgoing PUBLISH

The client publish path encodes and sends a PUBLISH, then waits for the expected acknowledgement:

```c
rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len,
        publish, pubCb ? 1 : 0);
...
rc = MqttPacket_Write(client, client->tx_buf, xfer);
...
rc = MqttClient_WaitType(client, &publish->resp, resp_type,
    publish->packet_id, client->cmd_timeout_ms);
```

Evidence: `wolfMQTT-master/src/mqtt_client.c:2169`, `wolfMQTT-master/src/mqtt_client.c:2213`, `wolfMQTT-master/src/mqtt_client.c:2287`.

This handles the normal QoS acknowledgement flow, but it does not show a retry path that re-encodes the same PUBLISH with `publish->duplicate = 1` after a timeout or reconnect.

The broker stores subscriptions and retained messages, but its public broker state does not contain an outgoing inflight PUBLISH store. The subscription record supports session persistence for subscriptions:

```c
typedef struct BrokerSub {
    char*   filter;
    char*   client_id; /* For session persistence */
    struct BrokerSub* next;
    struct BrokerClient* client; /* NULL if client disconnected */
    MqttQoS qos;
} BrokerSub;
```

Evidence: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:251`.

The broker context includes clients, subscriptions, retained messages, pending wills, and `next_packet_id`, but no queue of unacknowledged outgoing PUBLISH packets:

```c
typedef struct MqttBroker {
    ...
    word16  next_packet_id;
    BrokerClient* clients;
    BrokerSub*    subs;
    BrokerRetainedMsg* retained;
    BrokerPendingWill* pending_wills;
} MqttBroker;
```

Evidence: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:311`, `wolfMQTT-master/wolfmqtt/mqtt_broker.h:321`, `wolfMQTT-master/wolfmqtt/mqtt_broker.h:343`.

The reconnect handling for `clean_session == 0` reassociates subscriptions:

```c
if (!mc.clean_session) {
    BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
}
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:2768`, `wolfMQTT-master/src/mqtt_broker.c:2775`.

This preserves subscription state, but it does not re-send stored unacknowledged QoS>0 PUBLISH packets with DUP=1.

## Why This Is an Inconsistency

The implementation satisfies the narrow "do not propagate incoming DUP" requirement in the normal broker forwarding path. An incoming PUBLISH with DUP=1 is decoded into `pub`, but outgoing forwarded messages are built as fresh `out_pub` objects with `out_pub.duplicate = 0`.

The missing part is the second half of MQTT-3.3.1-3: the outgoing DUP flag must be determined solely by whether the outgoing PUBLISH is a retransmission. To satisfy that completely, the implementation would need to track outgoing QoS1/QoS2 PUBLISH packets that are not yet acknowledged, preserve them across the required CleanSession=0 reconnect scenario, and re-send them with the same Packet Identifier and DUP=1 when required.

wolfMQTT's observed broker/client code does not provide that complete retransmission state machine. Instead, the outgoing DUP value is manually assigned in the forwarding path and otherwise passed through from caller input to the encoder.

## Classification Rationale

Recommended category:

```text
DUP retransmission semantics incomplete
```

Recommended status:

```text
partial satisfaction
```

Reason:

wolfMQTT does not propagate the incoming PUBLISH DUP flag when forwarding to subscribers, so the independence portion of the standard is satisfied. However, outgoing DUP is not fully derived from an implementation-level retransmission state. The broker lacks a complete outgoing PUBLISH retransmission queue/state machine, and the encoder only writes the caller-provided `duplicate` field. Therefore the full "determined solely by whether the outgoing PUBLISH is a retransmission" rule is only partially implemented.
