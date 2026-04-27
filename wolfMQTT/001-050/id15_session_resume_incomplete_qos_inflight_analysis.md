# ID15 Analysis: Session Resume Only Restores Subscriptions, Not QoS In-Flight State

## Scope

This document analyzes finding 15:

- Result: partially satisfied
- Severity: high
- Issue: incomplete session resume coverage
- Claim: session resume only restores subscription mappings and does not restore QoS in-flight or pending messages.

Checked materials:

- Standard: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`
- Text extraction cross-check: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.docx`
- Codebase: `D:\project\conditionFuzzing\wolfMQTT-master`

Note: the `.doc` file is an old OLE Word document. The same MQTT 3.1.1 normative text is available in the adjacent `.docx`, which was used only to extract/search the English text while keeping the requested `.doc` as the standard source.

## English Standard Text

To avoid copying a large section of the standard, this section records the relevant clause IDs and short original English phrases.

| Clause | Key original English phrase | Required behavior |
|---|---|---|
| MQTT-3.1.2-4 | "MUST resume communications" | With `CleanSession=0`, the server resumes from existing session state for the same Client Identifier. |
| MQTT-3.1.2-5 | "MUST store further QoS 1 and QoS 2 messages" | After disconnection of a persistent session, matched QoS1/QoS2 messages must be stored as session state. |
| Server session state list | "Session state in the Server consists of" | Server-side state includes subscriptions, unacknowledged QoS1/QoS2 messages sent to the client, QoS1/QoS2 messages pending transmission, and incomplete QoS2 messages received from the client. |
| MQTT-4.1.0-1 | "MUST store Session state" | Session state must be stored for the entire session lifetime. |
| MQTT-4.4.0-1 | "MUST re-send any unacknowledged PUBLISH Packets" | On reconnect with `CleanSession=0`, both sides must resend unacknowledged QoS>0 PUBLISH and PUBREL packets using original Packet Identifiers. |
| MQTT-4.5.0-1 | "MUST add it to the Session state" | When the server takes ownership of an Application Message, it must add it to matching clients' session state. |

Therefore, MQTT 3.1.1 requires more than restoring a topic-filter subscription list. A persistent session also needs QoS delivery state: offline pending messages, unacknowledged outbound PUBLISH/PUBREL packets, and incomplete QoS2 handshake state.

## Related Code Description

### 1. Disconnect keeps only orphaned subscriptions

File: `wolfMQTT-master/src/mqtt_broker.c`

At lines 1397-1424, `BrokerSubs_OrphanClient()` implements session persistence by setting each matching subscription's client pointer to `NULL`.

Relevant behavior:

```c
broker->subs[i].client = NULL;
```

For the dynamic-memory path:

```c
cur->client = NULL;
```

This preserves the subscription record, but it does not preserve any QoS message payload, packet identifier, DUP flag, PUBREL state, or resend queue.

The same orphaning function is used on abnormal disconnect, normal DISCONNECT, and keepalive timeout:

- `mqtt_broker.c:3497-3504`
- `mqtt_broker.c:3581-3588`
- `mqtt_broker.c:3617-3624`

In all three paths, `clean_session == 0` calls `BrokerSubs_OrphanClient()`, then removes the `BrokerClient`.

### 2. Reconnect only reassociates subscription mappings

File: `wolfMQTT-master/src/mqtt_broker.c`

At lines 1745-1797, `BrokerSubs_ReassociateClient()` restores a persistent session by finding orphaned subscriptions with the same `client_id` and assigning the new broker client pointer.

Relevant behavior:

```c
s->client = new_bc;
```

The reconnect handler calls this function for `CleanSession=0`:

- `mqtt_broker.c:2768-2771`: duplicate Client ID takeover path
- `mqtt_broker.c:2775-2778`: no active old client, but orphaned subscriptions may exist

There is no call here to replay an offline queue, restore unacknowledged PUBLISH packets, restore PUBREL packets, or reuse original Packet Identifiers.

### 3. Publish fan-out skips disconnected persistent subscribers

File: `wolfMQTT-master/src/mqtt_broker.c`

At lines 3278-3330, incoming PUBLISH messages are fanned out only when the matching subscription has an online client pointer:

```c
if (sub->client != NULL &&
    sub->client->protocol_level != 0 &&
    BrokerTopicMatch(sub->filter, topic)) {
```

For persistent-session clients that disconnected with `CleanSession=0`, the subscription is intentionally orphaned with `sub->client == NULL`. Therefore, a matching QoS1/QoS2 message published while the client is offline is not stored for later delivery; it is simply outside this forwarding branch.

This is the core mismatch for the "pending transmission to the Client" part of server session state.

### 4. QoS acknowledgment handling has no stored in-flight table

File: `wolfMQTT-master/src/mqtt_broker.c`

At lines 3333-3348, the broker replies to incoming QoS1/QoS2 PUBLISH packets with PUBACK or PUBREC immediately. At lines 3365-3397 and 3399-3432, it decodes PUBREL/PUBREC and sends the next response immediately.

The main packet switch confirms there is no persisted state update for subscriber acknowledgments:

- `mqtt_broker.c:3553-3555`: `PUBLISH_ACK` is treated as delivery complete and no table entry is removed.
- `mqtt_broker.c:3566-3569`: `PUBLISH_COMP` is treated as delivery complete and no table entry is removed.

Because no in-flight table is created before sending QoS1/QoS2 messages, there is also nothing to restore or resend after reconnect.

### 5. Broker data model has subscriptions, retained messages, and wills, but no offline QoS queue

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h`

`BrokerSub` contains only a topic filter, stored `client_id`, current `client` pointer, and subscription QoS:

```c
struct BrokerClient* client;
MqttQoS qos;
```

`MqttBroker` contains:

- active clients
- subscriptions
- optional retained messages
- optional pending wills
- `next_packet_id`

It does not define a per-client session message queue or in-flight QoS state structure. There is no equivalent of:

- pending outbound QoS1/QoS2 messages for an offline persistent client
- unacknowledged outbound PUBLISH records
- unacknowledged PUBREL records
- incomplete inbound QoS2 records tied to a persistent session

## Inconsistency Reason

The implementation partially satisfies session resume because it preserves subscription mappings:

1. On disconnect with `clean_session=0`, subscriptions are orphaned instead of deleted.
2. On reconnect with the same Client ID and `clean_session=0`, those orphaned subscriptions are reassociated with the new `BrokerClient`.

However, the MQTT 3.1.1 session state requirement is broader than subscription mapping. The standard requires the server to maintain QoS state across the session:

1. QoS1/QoS2 messages that matched the disconnected client's subscriptions must be stored as session state.
2. QoS1/QoS2 messages already sent to the client but not completely acknowledged must remain in session state.
3. On reconnect with `CleanSession=0`, unacknowledged QoS>0 PUBLISH and PUBREL packets must be resent with their original Packet Identifiers.

wolfMQTT's broker code has no durable or in-memory session queue for those messages. Its reconnect path only relinks `BrokerSub.client`; its publish path only sends to online `sub->client` entries; its QoS acknowledgment handlers do not maintain a recoverable in-flight table.

## Final Conclusion

The finding is valid.

wolfMQTT is partially aligned with MQTT persistent sessions because it keeps and restores subscriptions for `clean_session=0`. It is not fully compliant for session resume because the restored state does not include QoS1/QoS2 pending, unacknowledged, or incomplete in-flight messages required by MQTT 3.1.1.

Risk impact: after a persistent-session client disconnects, QoS1/QoS2 messages published during the offline period, or QoS packets that were in-flight at disconnect time, can be lost instead of being resumed/redelivered on reconnect.
