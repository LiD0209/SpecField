# Packet Identifier Reuse State Is Not Centrally Modeled

## Summary

MQTT allows a Packet Identifier to be reused only after the corresponding acknowledgement has been processed. wolfMQTT has local cleanup behavior after acknowledgements are received, so a Packet Identifier can be reused after a completed QoS flow. However, this reuse is not managed through a central Packet Identifier state model.

In practice, wolfMQTT removes pending response entries after acknowledgement processing, but it does not maintain a single allocation state such as:

```text
unused -> in use -> acknowledged -> reusable
```

This makes the implementation partially aligned with the standard: reuse after acknowledgement works, but reuse is not governed by a unified allocator/release policy.

## Standard Requirement

MQTT Version 3.1.1, Section 2.3.1, "Packet Identifier":

Online source: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>

Original English requirement excerpts:

> currently unused Packet Identifier

> available for reuse after

Section 2.3.1 defines two connected requirements:

| Requirement | Meaning |
|---|---|
| New packets need an unused Packet Identifier | A new packet must not take a value that is still active in the session. |
| Reuse is allowed after acknowledgement processing | A value becomes reusable only after the corresponding acknowledgement packet has been processed. |

For the relevant packet flows, the reuse point is:

| Packet flow | Reuse point |
|---|---|
| QoS 1 `PUBLISH` | After processing the corresponding `PUBACK` |
| QoS 2 `PUBLISH` | After processing the corresponding `PUBCOMP` |
| `SUBSCRIBE` | After processing the corresponding `SUBACK` |
| `UNSUBSCRIBE` | After processing the corresponding `UNSUBACK` |

## Code Behavior

### Pending Response Registration

In `wolfMQTT-master/src/mqtt_client.c`, QoS 1 and QoS 2 `PUBLISH` packets register a pending response using the current `publish->packet_id`:

```c
rc = MqttClient_RespList_Add(client, resp_type,
    publish->packet_id, &publish->pendResp, &publish->resp);
```

The pending response entry stores the Packet Identifier:

```c
newResp->packet_id = packet_id;
newResp->packet_type = packet_type;
newResp->packet_obj = packet_obj;
```

This models "there is an acknowledgement outstanding", but it is a per-operation tracking object rather than a central Packet Identifier allocation table.

### Pending Response Removal After Acknowledgement

After a blocking `PUBLISH` operation receives the expected `PUBACK` or `PUBCOMP`, wolfMQTT removes the pending response entry:

```c
if (wm_SemLock(&client->lockClient) == 0) {
    MqttClient_RespList_Remove(client, &publish->pendResp);
    wm_SemUnlock(&client->lockClient);
}
```

`SUBSCRIBE` and `UNSUBSCRIBE` follow the same pattern after `SUBACK` and `UNSUBACK`:

```c
MqttClient_RespList_Remove(client, &subscribe->pendResp);
```

```c
MqttClient_RespList_Remove(client, &unsubscribe->pendResp);
```

This provides the observable effect that a completed Packet Identifier is no longer tracked as pending.

### Removal Is Not a Central Release Operation

`MqttClient_RespList_Remove` only unlinks a specific pending response object from the list:

```c
if (client->firstPendResp == tmpResp) {
    client->firstPendResp = tmpResp->next;
}
if (client->lastPendResp == tmpResp) {
    client->lastPendResp = tmpResp->prev;
}
```

It does not release the Packet Identifier into a central reusable pool, because no such pool exists in this code path.

### Broker-Side Generation Also Lacks Reuse State

In `wolfMQTT-master/src/mqtt_broker.c`, broker-side Packet Identifier generation increments and skips zero:

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

This function does not consult a central in-use/reusable state before returning a value.

## Runtime Reproduction

A runtime reproducer is available at:

`wolfMQTT/101-150/repro_packet_id_reuse_after_ack.c`

The reproducer uses a fake network layer:

| Step | Behavior |
|---|---|
| 1 | Send QoS 1 `PUBLISH` with Packet Identifier `7`. |
| 2 | Fake broker returns `PUBACK` with Packet Identifier `7`. |
| 3 | Check that pending entries for Packet Identifier `7` are gone. |
| 4 | Send another QoS 1 `PUBLISH` using Packet Identifier `7`. |
| 5 | Fake broker returns another `PUBACK` with Packet Identifier `7`. |

Build and run:

```powershell
gcc -DHAVE_CONFIG_H -DWOLFMQTT_MULTITHREAD -IwolfMQTT/101-150 -IwolfMQTT-master wolfMQTT/101-150/repro_packet_id_reuse_after_ack.c wolfMQTT-master/src/mqtt_client.c wolfMQTT-master/src/mqtt_socket.c wolfMQTT-master/src/mqtt_packet.c -o wolfMQTT/101-150/repro_packet_id_reuse_after_ack.exe
wolfMQTT/101-150/repro_packet_id_reuse_after_ack.exe
```

Observed output:

```text
first publish packet_id=7  rc=0 observed_packet_id=7 pending_after_first=0
second publish packet_id=7 rc=0 observed_packet_id=7 pending_after_second=0
writes=2 reads=4 ack_bytes_consumed=8
OBSERVED: Packet Identifier was reusable after PUBACK processing
```

The output confirms that, after `PUBACK` processing, wolfMQTT can reuse Packet Identifier `7` for a later QoS 1 `PUBLISH`.

## Inconsistency

| Expected by MQTT | Observed in wolfMQTT |
|---|---|
| Packet Identifier reuse is tied to acknowledgement processing. | Completed blocking operations remove their pending response entry after acknowledgement processing. |
| The implementation should distinguish unused, in-use, and reusable identifiers consistently. | The code uses local pending response objects, not a central Packet Identifier state table. |
| Reuse should be a controlled release-and-reallocate operation. | Reuse is possible as a side effect of pending response removal and caller-provided Packet Identifier values. |

## Root Cause

The root cause is that Packet Identifier lifetime is represented indirectly.

`MqttClient_RespList_Add` and `MqttClient_RespList_Remove` track pending acknowledgements, but they do not implement a complete allocator/releaser for Packet Identifier values. Once a pending response object is removed, there is no central state transition recording that the numeric Packet Identifier moved from "in use" to "reusable".

This is why the behavior is only partially modeled:

| State transition | Current implementation |
|---|---|
| Allocate unused Packet Identifier | Usually supplied by caller or generated by a simple counter. |
| Mark Packet Identifier in use | Stored inside a pending response object. |
| Process acknowledgement | Handled by wait/response logic. |
| Release Packet Identifier for reuse | Pending response object is removed, but no central release table is updated. |

## Impact

This is mainly a protocol-state clarity and maintainability issue.

Potential effects:

| Effect | Description |
|---|---|
| Partial protocol modeling | ACK-completed reuse works, but the Packet Identifier lifecycle is not explicit. |
| Harder correctness reasoning | It is difficult to prove that every new value comes from the currently reusable set. |
| Future regression risk | New send paths can bypass reuse semantics unless they manually follow the same implicit pattern. |
| Wraparound ambiguity | Counter-based generation has no central reusable set to consult after wrapping. |


## Suggested Fix

wolfMQTT should represent Packet Identifier lifetime explicitly for packets that require acknowledgements.

At minimum:

| Requirement | Description |
|---|---|
| Track in-use identifiers | Maintain a per-session set of Packet Identifiers that are awaiting acknowledgement. |
| Release on acknowledgement | Move the identifier back to the reusable set only after the correct acknowledgement is processed. |
| Allocate through one path | Route client-side and broker-side generation through the same unused-value selection logic. |
| Preserve caller compatibility | If callers provide Packet Identifiers manually, reject values that are not currently reusable. |

