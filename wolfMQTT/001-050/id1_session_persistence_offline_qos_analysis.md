# ID1 Analysis: Session Persistence Stores Only Subscriptions (No Offline QoS>0 Queue)

## Scope

This note verifies whether the following finding is real:

- `ID 1 | source_idx 0 | partial satisfied | high`
- Claim: only orphaned subscriptions are kept; offline QoS>0 messages are not stored after disconnect.

Target codebase: `wolfMQTT-master` broker path.

## English Normative Requirements (MQTT v3.1.1)

Source document: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`
(same normative text is present in `mqtt-v3.1.1-os.docx`).

Session persistence with `CleanSession=0` (`[MQTT-3.1.2-4]`, `[MQTT-3.1.2-5]`):

```text
If CleanSession is set to 0, the Server MUST resume communications with the
Client based on state from the current Session (as identified by the Client
identifier). If there is no Session associated with the Client identifier the
Server MUST create a new Session. The Client and Server MUST store the Session
after the Client and Server are disconnected [MQTT-3.1.2-4]. After the
disconnection of a Session that had CleanSession set to 0, the Server MUST store
further QoS 1 and QoS 2 messages that match any subscriptions that the client had
at the time of disconnection as part of the Session state [MQTT-3.1.2-5]. It MAY
also store QoS 0 messages that meet the same criteria.
```

Session state duration (`[MQTT-4.1.0-1]`):

```text
The Client and Server MUST store Session state for the entire duration of the
Session [MQTT-4.1.0-1].
```

Server-side session accumulation (`[MQTT-4.5.0-1]`):

```text
When a Server takes ownership of an incoming Application Message it MUST add it
to the Session state of those clients that have matching Subscriptions. Matching
rules are defined in Section 4.7 [MQTT-4.5.0-1].
```

Interpretation:

- For disconnected clients with `CleanSession=0`, storing further matched QoS1/QoS2 messages is a **MUST**, not SHOULD.
- Keeping only subscription metadata is insufficient for full session persistence semantics.

## Code Behavior in `wolfMQTT-master`

### 1) Disconnect path keeps subscriptions only

File: `wolfMQTT-master/src/mqtt_broker.c:1397`

```c
/* Orphan subscriptions for session persistence (clean_session=0).
 * Sets client pointer to NULL but keeps the subscription for reconnect. */
static void BrokerSubs_OrphanClient(MqttBroker* broker, BrokerClient* bc)
{
    int count = 0;
#ifdef WOLFMQTT_STATIC_MEMORY
    int i;
    for (i = 0; i < BROKER_MAX_SUBS; i++) {
        if (broker->subs[i].in_use && broker->subs[i].client == bc) {
            broker->subs[i].client = NULL;
            count++;
        }
    }
#else
    BrokerSub* cur = broker->subs;
    while (cur) {
        if (cur->client == bc) {
            cur->client = NULL;
            count++;
        }
        cur = cur->next;
    }
#endif
```

The function keeps the subscription but detaches the client pointer. It does not copy or queue pending QoS1/QoS2 messages.

The same orphaning function is called when a persistent-session client disconnects or times out:

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

### 2) Reconnect path reassociates subscriptions only

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
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            BrokerSub* s = &broker->subs[i];
            if (!s->in_use) continue;
            /* Check orphaned subs (client=NULL, client_id stored in sub) */
            if (s->client == NULL && BROKER_STR_VALID(s->client_id) &&
                XSTRCMP(s->client_id, client_id) == 0) {
                s->client = new_bc;
                count++;
            }
```

The reconnect path restores subscription ownership by assigning `s->client = new_bc`. There is no replay or drain of an offline QoS1/QoS2 queue here.

### 3) PUBLISH fan-out sends only to online subscribers

File: `wolfMQTT-master/src/mqtt_broker.c:3278`

```c
if (topic != NULL && (payload != NULL || pub.total_len == 0)) {
    /* Fan out to matching subscribers */
#ifdef WOLFMQTT_STATIC_MEMORY
    {
        int i;
        for (i = 0; i < BROKER_MAX_SUBS; i++) {
            BrokerSub* sub = &broker->subs[i];
            if (!sub->in_use) continue;
#else
    {
        BrokerSub* sub = broker->subs;
        while (sub) {
#endif
            if (sub->client != NULL &&
                sub->client->protocol_level != 0 &&
                BROKER_STR_VALID(sub->filter) &&
                BrokerTopicMatch(sub->filter, topic)) {
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
```

The forwarding condition requires `sub->client != NULL`. Orphaned persistent subscriptions have `sub->client == NULL`, so matching offline clients are skipped instead of receiving a stored session message.

### 4) Data model has subscriptions/retained/will, but no offline session message queue

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:251`

```c
typedef struct BrokerSub {
#ifdef WOLFMQTT_STATIC_MEMORY
    byte    in_use;
    char    filter[BROKER_MAX_FILTER_LEN];
    char    client_id[BROKER_MAX_CLIENT_ID_LEN]; /* For session persistence */
#else
    char*   filter;
    char*   client_id; /* For session persistence */
    struct BrokerSub* next;
#endif
    struct BrokerClient* client; /* NULL if client disconnected (session persisted) */
    MqttQoS qos;
} BrokerSub;
```

```c
typedef struct MqttBroker {
    BROKER_SOCKET_T listen_sock;
    word16  port;
    int     running;
    byte    log_level;
    MqttBrokerNet net;
    word16  next_packet_id;
#ifdef WOLFMQTT_STATIC_MEMORY
    BrokerClient clients[BROKER_MAX_CLIENTS];
    BrokerSub    subs[BROKER_MAX_SUBS];
#ifdef WOLFMQTT_BROKER_RETAINED
    BrokerRetainedMsg retained[BROKER_MAX_RETAINED];
#endif
#ifdef WOLFMQTT_BROKER_WILL
    BrokerPendingWill pending_wills[BROKER_MAX_PENDING_WILLS];
#endif
#else
    BrokerClient* clients;
    BrokerSub*    subs;
#ifdef WOLFMQTT_BROKER_RETAINED
    BrokerRetainedMsg* retained;
#endif
#ifdef WOLFMQTT_BROKER_WILL
    BrokerPendingWill* pending_wills;
#endif
#endif
} MqttBroker;
```

The broker state tracks subscriptions, optional retained messages, and optional pending wills. It does not define a per-client offline QoS1/QoS2 pending-delivery session queue.

## Why It Is Inconsistent with the Spec

1. Requirement level mismatch:
- Spec uses MUST (`[MQTT-3.1.2-5]`, `[MQTT-4.1.0-1]`, `[MQTT-4.5.0-1]`) for session state persistence of QoS1/QoS2 messages.

2. Implementation scope mismatch:
- Current broker persists subscription metadata (`orphan + reassociate`), but does not persist "further QoS1/QoS2 messages while disconnected".

3. Delivery path gap:
- Publish path has only "send to online subscriber" logic, without a "store for offline persistent session" branch.

## Final Conclusion

The reported issue is real.

- The implementation is **partially aligned** with persistent sessions because it keeps subscriptions for `clean_session=0`.
- It **does not satisfy** the MUST requirement to store further matched QoS1/QoS2 messages during disconnection as session state.

Therefore, this finding should be treated as a valid high-risk compliance gap.
