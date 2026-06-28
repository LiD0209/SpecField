# CONNACK Session Present Is Not Set When a Persistent Session Is Resumed

## Summary

wolfMQTT can preserve subscriptions for a client that disconnects with `CleanSession=0` and later reconnects with the same Client Identifier. However, when that stored session is resumed, the broker still sends a CONNACK with `Session Present=0`.

For MQTT 3.1.1, this is incomplete CONNACK semantics. If the server accepts a connection and has stored session state for the client, the CONNACK Session Present flag must be set to `1` so the client can know that an existing session was resumed.

Observed CONNACK:

```text
20 02 00 00
```

Expected CONNACK when stored session state is resumed:

```text
20 02 01 00
```

The return code is accepted in both cases, but the third byte differs:

| Byte | Current | Expected | Meaning |
|---:|---:|---:|---|
| Connect Acknowledge Flags | `0x00` | `0x01` | Session Present should be `1` |
| Connect Return code | `0x00` | `0x00` | Connection accepted |

## Standard Reference

Source: [OASIS MQTT Version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `3.2.2.2 Session Present`.

Short original English excerpts from Section `3.2.2.2`:

```text
"MUST set Session Present to 1"
```

```text
"MUST set Session Present to 0"
```

In prose, Section `3.2.2.2` requires the Session Present bit to reflect whether a successful `CleanSession=0` connection found stored session state for the supplied Client Identifier. If stored state exists, Session Present is `1`; if no stored state exists, or if the accepted connection used `CleanSession=1`, Session Present is `0`.

Relevant section: `3.1.2.4 Clean Session`.

This section defines the session behavior behind the CONNACK flag. With `CleanSession=0`, the server must resume communications with the client based on session state associated with the Client Identifier, if such state exists.

## Expected Behavior

For a successful MQTT 3.1.1 connection:

| Client CONNECT state | Server stored session state | Expected CONNACK flags |
|---|---|---:|
| `CleanSession=1` | Irrelevant | `0x00` |
| `CleanSession=0` | No stored session state | `0x00` |
| `CleanSession=0` | Stored session state exists | `0x01` |

In the last case, the server must inform the client that its previous session was resumed. This matters because clients use Session Present to decide whether they need to resubscribe and whether prior session state was retained.

## Code Description

### Persistent subscriptions are orphaned on disconnect

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerSubs_OrphanClient()`

When a client disconnects with a persistent session, wolfMQTT keeps its subscriptions by clearing the live client pointer instead of deleting the subscription:

```c
if (cur->client == bc) {
    cur->client = NULL;
    count++;
}
```

The comment describes this as session persistence:

```c
/* Orphan subscriptions for session persistence (clean_session=0).
 * Sets client pointer to NULL but keeps the subscription for reconnect. */
```

This means wolfMQTT has a form of stored session state for the client.

### Persistent subscriptions are reassociated on reconnect

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerSubs_ReassociateClient()`

On reconnect, the broker searches for orphaned subscriptions with the same Client Identifier and attaches them to the new client:

```c
if (s->client == NULL && BROKER_STR_VALID(s->client_id) &&
    XSTRCMP(s->client_id, client_id) == 0) {
    s->client = new_bc;
    count++;
}
```

`BrokerHandle_Connect()` calls this path when a client connects with `CleanSession=0`:

```c
else if (!mc.clean_session) {
    /* No existing client, but check for orphaned subs from
     * a previous session (clean_session=0 reconnect) */
    BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
}
```

At this point, the broker has detected and resumed stored session state.

### CONNACK flags are still forced to zero

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

After possible reassociation, the broker initializes the CONNACK as accepted with flags set to zero:

```c
ack.flags = 0;
ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
```

There is no state variable recording whether `BrokerSubs_ReassociateClient()` actually found stored session state, and no later branch that sets:

```c
ack.flags = 0x01;
```

or an equivalent Session Present constant when a stored session was resumed.

### CONNACK encoder serializes the provided flags directly

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_ConnectAck()`

The encoder writes the flags byte directly from `connect_ack->flags`:

```c
*tx_payload++ = connect_ack->flags;
*tx_payload++ = connect_ack->return_code;
```

Therefore, if `BrokerHandle_Connect()` leaves `ack.flags` as `0`, the wire CONNACK necessarily advertises `Session Present=0`.

## Reproduction

A focused reproducer is available at:

```text
wolfMQTT/201-250/repro_connack_session_present_228.c
```

Build and run:

```powershell
gcc -IwolfMQTT-master -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER -DWOLFMQTT_BROKER_CUSTOM_NET -DNO_MAIN_DRIVER '-DWOLFMQTT_BROKER_GET_TIME_S()=((WOLFMQTT_BROKER_TIME_T)0)' '-DBROKER_SLEEP_MS(ms)=do{}while(0)' wolfMQTT/201-250/repro_connack_session_present_228.c wolfMQTT-master/src/mqtt_packet.c wolfMQTT-master/src/mqtt_socket.c wolfMQTT-master/src/mqtt_client.c -o wolfMQTT/201-250/repro_connack_session_present_228.exe
.\wolfMQTT\201-250\repro_connack_session_present_228.exe
```

Observed output:

```text
add persistent subscription rc=0
orphaned subscription for client_id=cid1
reconnect rc=4 writes=1
connack bytes: 20 02 00 00
session_present_flag=0 return_code=0 expected_session_present=1
repro verdict: issue reproduced: stored session was resumed but CONNACK Session Present stayed 0
```

The test creates a persistent subscription, orphans it as stored session state, reconnects the same Client Identifier with `CleanSession=0`, and captures the CONNACK. The broker resumes the subscription but sends `Session Present=0`.

## Inconsistency

| Standard requirement | wolfMQTT behavior |
|---|---|
| If accepted `CleanSession=0` connection has stored session state, CONNACK Session Present must be `1` | The broker reassociates orphaned subscriptions but sends CONNACK flags `0x00` |
| Session Present communicates whether prior session state was resumed | The client receives `Session Present=0` even though stored subscriptions were resumed |
| CONNACK flags should reflect session-state lookup result | `ack.flags` is unconditionally initialized to `0` after the lookup/reassociation logic |

## Root Cause

The broker has session-resume behavior but does not propagate the result of that behavior into CONNACK construction.

`BrokerSubs_ReassociateClient()` can find and attach stored subscriptions, but it returns `void`. The caller does not know whether stored session state was present. Later, `BrokerHandle_Connect()` sets `ack.flags = 0` for every accepted connection and never changes it based on the reassociation result.

In short:

```text
stored session state is resumed
but
CONNACK Session Present is always encoded as 0
```

## Suggested Fix Direction

Make session-state lookup return whether any stored state was found, then use that result when constructing the CONNACK.

One possible direction:

```c
int session_present = 0;

if (!mc.clean_session) {
    session_present = BrokerSubs_ReassociateClient(broker, bc->client_id, bc);
}

ack.flags = session_present ? 0x01 : 0x00;
ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
```

The actual implementation should use a named constant for the Session Present bit if one exists or add one near the CONNACK flag definitions. It should also preserve the existing behavior that refused CONNACK packets use `Session Present=0`.
