# wolfMQTT QoS2 Method B Store/Discard Lifecycle Missing

## Summary

wolfMQTT broker implements the visible QoS2 response packets, but it does not maintain the receiver-side Method B lifecycle for inbound `Packet Identifier` values.

The missing lifecycle is:

```text
store Packet Identifier after inbound QoS2 PUBLISH
keep it while waiting for PUBREL
discard it after completing PUBREL/PUBCOMP
```

Without this state, the broker cannot implement Method B as a semantic state machine. It can send `PUBREC` and `PUBCOMP`, but it has no stored receiver-side state to decide whether an inbound QoS2 `PUBLISH` is new or a retransmission.

## Standard Reference

MQTT standard: [MQTT Version 3.1.1, OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)

Relevant section: `4.3.3 QoS 2: Exactly once delivery`

Relevant original English text from the standard:

```text
QoS 2: Exactly once delivery
Store <Packet Identifier>
Discard <Packet Identifier>
```

The standard describes two receiver-side approaches for QoS2. Under Method B, the receiver stores the `Packet Identifier`, starts onward delivery, later receives the matching `PUBREL`, sends `PUBCOMP`, and discards the stored identifier. This stored identifier is what lets the receiver distinguish an in-progress QoS2 exchange from a later new publication.

## Expected Behavior

For Method B, the broker should keep per-client inbound QoS2 state:

```text
client/session + Packet Identifier -> waiting for PUBREL
```

Expected lifecycle:

```text
PUBLISH QoS2, Packet Identifier=N
  store N
  forward the message once
  send PUBREC N

PUBREL N
  send PUBCOMP N
  discard N
```

After discarding `N`, a later QoS2 `PUBLISH` with the same `Packet Identifier` can be treated as a new publication.

## Code Behavior

The broker client state structure is defined here:

```text
wolfMQTT-master/wolfmqtt/mqtt_broker.h:194
```

`BrokerClient` contains connection state, socket buffers, session fields, will fields, and an embedded `MqttClient`. It does not contain a per-client inbound QoS2 table such as:

```text
Packet Identifier -> waiting for PUBREL
```

The broker has a broker-wide `next_packet_id` field:

```text
wolfMQTT-master/wolfmqtt/mqtt_broker.h:321
```

That field is for assigning identifiers to packets sent by the broker. It is not a cache for inbound QoS2 identifiers received from a publishing client.

The inbound `PUBLISH` path decodes and handles the packet immediately:

```text
wolfMQTT-master/src/mqtt_broker.c:3207
```

The broker then performs fan-out to matching subscribers:

```text
wolfMQTT-master/src/mqtt_broker.c:3278
wolfMQTT-master/src/mqtt_broker.c:3315
```

Only after that does it send the QoS response:

```text
wolfMQTT-master/src/mqtt_broker.c:3333
wolfMQTT-master/src/mqtt_broker.c:3335
wolfMQTT-master/src/mqtt_broker.c:3341
```

The `PUBREL` handler decodes the packet and immediately sends `PUBCOMP`:

```text
wolfMQTT-master/src/mqtt_broker.c:3375
wolfMQTT-master/src/mqtt_broker.c:3389
```

There is no code path that stores the inbound `Packet Identifier` after `PUBLISH`, checks it while waiting for `PUBREL`, or discards it after `PUBCOMP`.

## Runtime Evidence

A local broker test exercised this QoS2 flow:

```text
PUBLISH QoS2, Packet Identifier=7, payload=first
PUBREC 7
duplicate PUBLISH QoS2, Packet Identifier=7, DUP=1, payload=first
PUBREC 7
PUBREL 7
PUBCOMP 7
new PUBLISH QoS2, Packet Identifier=7, payload=second
PUBREC 7
```

Observed result:

```text
PUBREC_FIRST 50 02 00 07
PUBREC_DUP_BEFORE_PUBREL 50 02 00 07
PUBCOMP 70 02 00 07
PUBREC_REUSE_AFTER_PUBCOMP 50 02 00 07
CHECK_WAITING_PUBREL_DEDUP FAIL_DUPLICATE_FORWARDED
CHECK_REUSE_AFTER_PUBCOMP PASS_NEW_PUBLICATION_ACCEPTED
OVERALL FAIL_METHOD_B_STATE_MISSING
```

This shows that the broker can emit the expected control packets, but it lacks the stored receiver-side state needed by Method B.

## Inconsistency Reason

The standard requires Method B to maintain a stored `Packet Identifier` lifecycle. wolfMQTT broker currently treats QoS2 as a sequence of immediate packet responses:

```text
receive PUBLISH -> forward -> send PUBREC
receive PUBREL  -> send PUBCOMP
```

The missing state explains all three symptoms:

- the client state structure has no Method B storage
- the inbound QoS2 `PUBLISH` path does not cache the `Packet Identifier`
- the flow has no explicit store/check/discard state machine

## Impact

This is a high-severity protocol correctness issue for deployments that rely on QoS2 exactly-once semantics.

It is not primarily a memory safety issue. The risk is duplicated application delivery or incorrect business behavior when clients retransmit QoS2 messages.

## Fix Direction

Add receiver-side QoS2 state to each broker client or persisted session:

```text
inbound Packet Identifier -> waiting for PUBREL
```

Then update the broker flow so that:

- first inbound QoS2 `PUBLISH` stores the identifier, forwards once, and sends `PUBREC`
- inbound `PUBREL` sends `PUBCOMP` and discards the stored identifier
- the same identifier can be reused only after the previous QoS2 exchange has completed
