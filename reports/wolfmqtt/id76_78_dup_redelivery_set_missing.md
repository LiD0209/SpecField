# PUBLISH Re-delivery Does Not Automatically Set DUP=1

## Summary

MQTT 3.1.1 requires a Client or Server to set the PUBLISH DUP flag to 1 when it attempts to re-deliver a PUBLISH packet. In wolfMQTT, the PUBLISH encoder can encode a caller-supplied `duplicate` value, but the observed client and broker code does not provide an automatic re-delivery path that changes DUP to 1 when a PUBLISH is retransmitted.

Classification: not satisfied.

## MQTT 3.1.1 Requirement

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), Sections 3.3.1.1 and 4.4.

Relevant sections:

- Section 3.3.1.1, PUBLISH fixed header, DUP flag.
- Section 4.4, Message delivery retry.

Normative excerpts:

```text
"The DUP flag MUST be set to 1 by the Client or Server when it attempts to re-deliver a PUBLISH Packet"
"When a Client reconnects with CleanSession set to 0, both the Client and Server MUST re-send any unacknowledged PUBLISH Packets (where QoS > 0) and PUBREL Packets using their original Packet Identifiers"
```

Detailed English description of the standard requirement:

```text
If an MQTT Client or Server sends a PUBLISH packet again as a re-delivery of an earlier PUBLISH attempt, the DUP flag in that re-delivered PUBLISH packet must be set to 1.

MQTT 3.1.1 specifically requires re-delivery of unacknowledged QoS>0 PUBLISH packets when a Client reconnects with CleanSession set to 0. Those re-delivered PUBLISH packets must keep their original Packet Identifiers, and because they are re-deliveries, they must be sent with DUP=1.
```

## Code Evidence: Encoder Only Uses Caller-Supplied DUP

The generic PUBLISH encoder passes the caller-provided `publish->duplicate` value into fixed-header encoding:

```c
header_len = MqttEncode_FixedHeader(tx_buf, tx_buf_len,
    variable_len + payload_len, publish->type,
    publish->retain, publish->qos, publish->duplicate);
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:1341`.

The fixed-header encoder sets the DUP bit only when the argument is already non-zero:

```c
if (duplicate) {
    header->type_flags |=
        MQTT_PACKET_FLAGS_SET(MQTT_PACKET_FLAG_DUPLICATE);
}
```

Evidence: `wolfMQTT-master/src/mqtt_packet.c:169`.

This means the encoder can represent DUP=1, but it does not decide when a PUBLISH is a re-delivery.

## Code Evidence: Client Publish Path Does Not Auto-Retry with DUP=1

The client publish path encodes the PUBLISH once:

```c
rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len,
        publish, pubCb ? 1 : 0);
```

Evidence: `wolfMQTT-master/src/mqtt_client.c:2169`.

It then writes the packet and waits for the QoS response:

```c
rc = MqttPacket_Write(client, client->tx_buf, xfer);
...
rc = MqttClient_WaitType(client, &publish->resp, resp_type,
    publish->packet_id, client->cmd_timeout_ms);
```

Evidence: `wolfMQTT-master/src/mqtt_client.c:2213`, `wolfMQTT-master/src/mqtt_client.c:2287`.

No code in this path sets `publish->duplicate = 1` for a retry after timeout or reconnect.

## Code Evidence: Broker Forwarding Clears DUP and Lacks Re-delivery Store

The broker forwarding path explicitly sends first-attempt outgoing PUBLISH packets with DUP=0:

```c
out_pub.duplicate = 0;
rc = MqttEncode_Publish(sub->client->tx_buf,
        BROKER_CLIENT_TX_SZ(sub->client), &out_pub, 0);
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:3305`, `wolfMQTT-master/src/mqtt_broker.c:3315`.

The broker has subscription persistence for CleanSession=0 reconnects, but no observed queue of unacknowledged outgoing PUBLISH packets that can be re-sent with DUP=1:

```c
if (!mc.clean_session) {
    BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
}
```

Evidence: `wolfMQTT-master/src/mqtt_broker.c:2768`, `wolfMQTT-master/src/mqtt_broker.c:2775`.

## Why This Is an Inconsistency

The standard does not merely allow DUP=1 on re-delivery; it requires it. wolfMQTT exposes a `duplicate` field and can encode DUP=1 if the caller manually sets it, but the implementation does not provide an automatic protocol-level mechanism that:

- tracks an unacknowledged QoS>0 PUBLISH,
- re-sends it in the required re-delivery case,
- preserves the original Packet Identifier,
- and sets DUP=1 on that re-delivery.

Therefore the required "re-delivered PUBLISH => DUP=1" behavior is not guaranteed by the library implementation.

## Classification Rationale

Recommended category:

```text
DUP re-delivery set missing
```

Recommended status:

```text
not satisfied
```

Reason:

The code can encode a manually supplied DUP value, but no automatic PUBLISH re-delivery path was found that sets DUP=1 when retransmitting. The requirement is therefore not implemented as a protocol-level guarantee.
