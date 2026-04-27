# ID27 Analysis: Reconnect Retransmission of Inflight PUBLISH/PUBREL Is Missing

## Scope

This document describes the following finding:

| ID | source_idx | Status | Risk | Category | Summary |
|---:|---:|---|---|---|---|
| 27 | 26 | Not satisfied | high | Reconnect retransmission semantics missing | There is no offline inflight queue and no reconnect flow that re-sends unacknowledged `PUBLISH` / `PUBREL` with the original `packet_id`. |

Checked materials:

- Standard: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`
- Codebase: `D:\project\conditionFuzzing\wolfMQTT-master`

## English Standard Text

The relevant MQTT 3.1.1 rule is in Section `4.4 Message delivery retry`, clause `[MQTT-4.4.0-1]`.

Short original English excerpts:

```text
"CleanSession set to 0"
"MUST re-send any unacknowledged PUBLISH Packets"
"and PUBREL Packets"
"using their original Packet Identifiers"
```

The full rule means:

- The trigger is a client reconnecting with `CleanSession=0`.
- Both the Client and Server are covered by this requirement.
- The packets to re-send are unacknowledged `PUBLISH` packets with `QoS > 0` and unacknowledged `PUBREL` packets.
- The re-send must reuse the original Packet Identifier. Allocating a new packet id is not equivalent.

The Packet Identifier rule in Section `2.3.1 Packet Identifier` is consistent with this:

```text
"same Packet Identifier in subsequent re-sends"
"same conditions apply to a Server"
```

So this is a MUST-level retransmission requirement, not an optional QoS optimization.

## Expected Behavior

For a persistent MQTT 3.1.1 session:

1. A client connects with `CleanSession=0`.
2. The Server sends a QoS1/QoS2 `PUBLISH` to that client, or sends a `PUBREL` during a QoS2 exchange.
3. The packet is not completely acknowledged before the network connection is lost.
4. The same client reconnects with the same ClientId and `CleanSession=0`.
5. The Server must re-send the unacknowledged `PUBLISH` or `PUBREL`.
6. The re-sent packet must use the original `packet_id`.

This requires some form of per-client inflight session state, such as:

- outbound QoS1 `PUBLISH` waiting for `PUBACK`;
- outbound QoS2 `PUBLISH` waiting for `PUBREC`;
- outbound QoS2 `PUBREL` waiting for `PUBCOMP`;
- original packet identifiers associated with those pending packets.

## Code Description

### 1. Reconnect restores subscriptions only

File: `wolfMQTT-master/src/mqtt_broker.c:1745`

```c
static void BrokerSubs_ReassociateClient(MqttBroker* broker,
    const char* client_id, BrokerClient* new_bc)
{
    int count = 0;
    if (broker == NULL || client_id == NULL || client_id[0] == '\0' ||
        new_bc == NULL) {
        return;
    }
```

The function searches stored subscriptions for the same ClientId and reassigns them to the new connection:

```c
if (s->client == NULL && BROKER_STR_VALID(s->client_id) &&
    XSTRCMP(s->client_id, client_id) == 0) {
    s->client = new_bc;
    count++;
}
```

This handles subscription ownership after reconnect. It does not traverse an inflight message list, rebuild a pending QoS retransmission queue, or re-send saved `PUBLISH` / `PUBREL` packets.

### 2. CONNECT path calls only subscription reassociation

File: `wolfMQTT-master/src/mqtt_broker.c:2768`

```c
if (!mc.clean_session) {
    /* Reassociate old client's subs to new client */
    BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
}
```

File: `wolfMQTT-master/src/mqtt_broker.c:2775`

```c
else if (!mc.clean_session) {
    /* No existing client, but check for orphaned subs from
     * a previous session (clean_session=0 reconnect) */
    BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
}
```

Both reconnect branches call `BrokerSubs_ReassociateClient()`. There is no adjacent step that re-sends unacknowledged QoS packets or restores original packet identifiers.

### 3. Disconnect preserves subscriptions, not inflight packets

File: `wolfMQTT-master/src/mqtt_broker.c:3497`

```c
/* Session persistence: keep subs if clean_session=0 */
if (bc->clean_session) {
    BrokerSubs_RemoveClient(broker, bc);
}
else {
    BrokerSubs_OrphanClient(broker, bc);
}
BrokerClient_Remove(broker, bc);
```

For `clean_session=0`, the disconnect path calls `BrokerSubs_OrphanClient()` so subscriptions remain available for a later reconnect. It does not persist any per-client unacknowledged `PUBLISH` / `PUBREL` state before removing the broker client object.

### 4. New outbound PUBLISH packets receive newly allocated packet ids

File: `wolfMQTT-master/src/mqtt_broker.c:1628`

```c
static word16 BrokerNextPacketId(MqttBroker* broker)
{
    word16 id = broker->next_packet_id;
    broker->next_packet_id++;
    if (broker->next_packet_id == 0) {
        broker->next_packet_id = 1; /* wrap: skip 0 */
    }
    return id;
}
```

File: `wolfMQTT-master/src/mqtt_broker.c:3278`

```c
if (topic != NULL && (payload != NULL || pub.total_len == 0)) {
    /* Fan out to matching subscribers */
```

File: `wolfMQTT-master/src/mqtt_broker.c:3301`

```c
if (eff_qos >= MQTT_QOS_1) {
    out_pub.packet_id = BrokerNextPacketId(broker);
}
```

This is appropriate for a new outbound QoS message. It is not sufficient for retransmission after reconnect, because `[MQTT-4.4.0-1]` requires the original Packet Identifier to be reused.

### 5. QoS2 PUBREC/PUBREL handling is online and stateless

File: `wolfMQTT-master/src/mqtt_broker.c:3401`

```c
static int BrokerHandle_PublishRec(BrokerClient* bc, int rx_len)
{
    ...
    rc = MqttDecode_PublishResp(bc->rx_buf, rx_len,
            MQTT_PACKET_TYPE_PUBLISH_REC, &resp);
```

File: `wolfMQTT-master/src/mqtt_broker.c:3425`

```c
rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
        MQTT_PACKET_TYPE_PUBLISH_REL, &resp);
```

This path receives `PUBREC` and immediately sends `PUBREL` using the decoded response packet id. It does not store an outbound `PUBREL` as an inflight record to be resent after a later reconnect.

Similarly, incoming `PUBREL` is handled by immediately sending `PUBCOMP`:

File: `wolfMQTT-master/src/mqtt_broker.c:3374`

```c
WBLOG_DBG(bc->broker, "broker: PUBLISH_REL recv sock=%d len=%d", (int)bc->sock, rx_len);
```

File: `wolfMQTT-master/src/mqtt_broker.c:3389`

```c
rc = MqttEncode_PublishResp(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc),
        MQTT_PACKET_TYPE_PUBLISH_COMP, &resp);
```

These online QoS handlers do not create persistent QoS2 session state for reconnect retransmission.

### 6. Broker data model has no per-client inflight queue

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:224`

```c
BROKER_SOCKET_T sock;
byte    protocol_level;
word16  keep_alive_sec;
WOLFMQTT_BROKER_TIME_T last_rx;
byte    clean_session;
byte    connected;       /* set after successful CONNECT handshake */
```

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:251`

```c
typedef struct BrokerSub {
    ...
    char*   client_id; /* For session persistence */
    struct BrokerSub* next;
    ...
    struct BrokerClient* client; /* NULL if client disconnected (session persisted) */
    MqttQoS qos;
} BrokerSub;
```

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:311`

```c
typedef struct MqttBroker {
    BROKER_SOCKET_T listen_sock;
    word16  port;
    int     running;
    byte    log_level;
    MqttBrokerNet net;
    word16  next_packet_id;
```

The visible broker model tracks clients, subscriptions, retained messages, pending wills, and a global `next_packet_id`. It does not define a per-client inflight table containing saved outbound `PUBLISH` / `PUBREL` packets and their original packet ids.

## Inconsistency Reason

The standard requires persistent-session retransmission state. wolfMQTT's broker implementation keeps only enough session state to restore subscriptions. That partially supports persistent subscriptions, but it does not preserve the QoS handshake state needed by `[MQTT-4.4.0-1]`.

The key mismatch is:

- Standard requirement: on `CleanSession=0` reconnect, re-send unacknowledged `PUBLISH(QoS>0)` and `PUBREL` using original packet identifiers.
- Implementation behavior: on reconnect, reattach orphaned subscriptions; new outbound QoS messages use `BrokerNextPacketId()`; online QoS2 response handling is not persisted.

Therefore, the implementation cannot guarantee original-packet-id retransmission after reconnect.

## Conclusion

The issue is real and should remain `Not satisfied / high`.

`ID27` is related to the broader session persistence gap, but it is more specific than "offline QoS messages are not stored". It should be tracked as a separate sub-issue:

```text
Reconnect retransmission semantics missing:
no per-client inflight queue and no original-packet-id re-send flow for
unacknowledged PUBLISH/PUBREL after CleanSession=0 reconnect.
```
