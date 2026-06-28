# wolfMQTT QoS2 Duplicate PUBLISH Forwarded Before PUBREL

## Summary

wolfMQTT broker can forward a duplicate inbound QoS2 `PUBLISH` while the original QoS2 exchange is still waiting for `PUBREL`.

This is the runtime consequence of missing receiver-side QoS2 duplicate detection. During the `PUBLISH -> PUBREC -> PUBREL -> PUBCOMP` flow, a retransmitted `PUBLISH` with the same `Packet Identifier` should cause another `PUBREC`, but it should not cause another onward delivery of the same application message.

## Standard Reference

MQTT standard: [MQTT Version 3.1.1, OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)

Relevant section: `4.3.3 QoS 2: Exactly once delivery`

Relevant original English text from the standard:

```text
QoS 2: Exactly once delivery
Store <Packet Identifier>
PUBREL <Packet Identifier>
Send PUBCOMP <Packet Identifier>
```

The standard's QoS2 flow requires the receiver to preserve enough state between `PUBREC` and `PUBREL` to avoid duplicate onward delivery. Under Method B, this state is the stored `Packet Identifier`.

## Expected Behavior

Expected behavior before the matching `PUBREL` is received:

```text
Client -> Broker: PUBLISH QoS2, Packet Identifier=N
Broker -> Subscriber: forward application message once
Broker -> Client: PUBREC N

Client -> Broker: PUBLISH QoS2, Packet Identifier=N, DUP=1
Broker -> Client: PUBREC N
Broker -> Subscriber: no second forward
```

The duplicate `PUBLISH` is part of the same in-progress QoS2 exchange. It should refresh the acknowledgement, not duplicate the application-level delivery.

## Code Behavior

The broker decodes every inbound `PUBLISH` here:

```text
wolfMQTT-master/src/mqtt_broker.c:3207
```

It then enters the fan-out path for matching subscribers:

```text
wolfMQTT-master/src/mqtt_broker.c:3278
wolfMQTT-master/src/mqtt_broker.c:3291
wolfMQTT-master/src/mqtt_broker.c:3315
wolfMQTT-master/src/mqtt_broker.c:3322
```

The QoS response is sent after the forwarding logic:

```text
wolfMQTT-master/src/mqtt_broker.c:3333
wolfMQTT-master/src/mqtt_broker.c:3341
```

The dispatcher routes inbound `PUBREL` to the `PUBCOMP` handler:

```text
wolfMQTT-master/src/mqtt_broker.c:3561
wolfMQTT-master/src/mqtt_broker.c:3564
```

The important missing step is before fan-out: there is no check for an existing inbound QoS2 `Packet Identifier` that is still waiting for `PUBREL`. Because of that, a retransmitted QoS2 `PUBLISH` follows the same forwarding path as the first `PUBLISH`.

## Runtime Reproduction

The issue was reproduced with a local broker and raw MQTT packets:

```text
subscriber subscribes to qos2-method-b/test
publisher sends QoS2 PUBLISH, packet_id=7, payload=first
broker returns PUBREC
publisher retransmits QoS2 PUBLISH, packet_id=7, DUP=1, payload=first
broker returns PUBREC again
subscriber receives payload=first again
publisher sends PUBREL
broker returns PUBCOMP
```

Observed result:

```text
FORWARD_AFTER_FIRST 1 [{'topic': 'qos2-method-b/test', 'qos': 0, 'packet_id': None, 'payload': 'first'}]
FORWARD_AFTER_DUP_BEFORE_PUBREL 1 [{'topic': 'qos2-method-b/test', 'qos': 0, 'packet_id': None, 'payload': 'first'}]
FORWARD_AFTER_PUBREL_ONLY 0 []
CHECK_WAITING_PUBREL_DEDUP FAIL_DUPLICATE_FORWARDED
```

Broker log evidence:

```text
broker: PUBLISH fwd sock=5 -> sock=4 topic=qos2-method-b/test qos=0 len=5
broker: PUBRESP send sock=5 qos=2 packet_id=7
broker: PUBLISH fwd sock=5 -> sock=4 topic=qos2-method-b/test qos=0 len=5
broker: PUBRESP send sock=5 qos=2 packet_id=7
```

The second forward is the protocol violation.

## Inconsistency Reason

The implementation performs duplicate-sensitive work before it has any duplicate detection:

```text
decode PUBLISH
match subscriptions
forward payload
send PUBREC
```

The standard requires a state-aware branch:

```text
if Packet Identifier is new:
  store it
  forward once
  send PUBREC

if Packet Identifier is already waiting for PUBREL:
  send PUBREC
  do not forward again
```

wolfMQTT broker has the acknowledgement behavior, but it lacks the waiting-for-`PUBREL` duplicate detection state. Therefore a retransmission becomes a second application delivery.

## Impact

This issue breaks QoS2 exactly-once delivery at the broker receive side.

Potential impact:

- subscribers can receive duplicate messages
- command or transaction handlers can execute twice
- a malicious or unstable client can trigger repeated duplicate delivery by resending the same QoS2 `PUBLISH` before `PUBREL`

The observed behavior is especially risky for non-idempotent application messages such as control commands, billing events, order updates, or state transitions.

## Fix Direction

Before fan-out, the broker should check per-client inbound QoS2 state:

```text
client/session + Packet Identifier -> waiting for PUBREL
```

Required behavior:

- first QoS2 `PUBLISH` with a new identifier: store, forward once, send `PUBREC`
- duplicate QoS2 `PUBLISH` with an identifier waiting for `PUBREL`: send `PUBREC`, do not forward
- matching `PUBREL`: send `PUBCOMP`, clear the waiting state
