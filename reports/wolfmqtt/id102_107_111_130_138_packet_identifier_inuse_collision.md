# Packet Identifier In-Use Collision Is Not Rejected

## Summary

MQTT requires each new QoS-related Control Packet to use a Packet Identifier that is not currently in use. wolfMQTT validates that outbound Packet Identifiers are non-zero, but it does not maintain a complete in-use collision check before registering or sending a new packet.

The result is that two new in-flight QoS 1 `PUBLISH` packets can use the same Packet Identifier at the same time. The pending response list can also hold multiple entries with the same Packet Identifier.

## Standard Requirement

MQTT Version 3.1.1, Section 2.3.1, "Packet Identifier":

Online source: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>

Original English requirement excerpts:

> MUST assign it a currently unused Packet Identifier

> becomes available for reuse

This section defines the core rule: when a Client sends a new packet that requires a Packet Identifier, it must choose one that is currently unused. The Packet Identifier only becomes reusable after the corresponding acknowledgement has been processed. The same section also states that the same conditions apply to the Server when it sends these packet types.

MQTT Version 3.1.1, Section 4.3.2, "QoS 1: At least once delivery":

Online source: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>

Original English requirement excerpt:

> different Packet Identifiers

This QoS 1 flow describes that later application messages are sent using different Packet Identifiers while earlier ones are still in progress.

MQTT Version 3.1.1, Section 4.3.3, "QoS 2: Exactly once delivery":

Online source: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>

The QoS 2 flow has the same practical requirement: a new QoS 2 delivery must not collide with an existing in-flight Packet Identifier.

## Code Behavior

### Encoding Only Checks Non-Zero

In `wolfMQTT-master/src/mqtt_packet.c`, `MqttEncode_Publish` rejects `packet_id == 0` for QoS 1 and QoS 2:

```c
if (publish->qos > MQTT_QOS_0) {
    if (publish->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }
    variable_len += MQTT_DATA_LEN_SIZE; /* For packet_id */
}
```

The encoder later writes the caller-provided value:

```c
if (publish->qos > MQTT_QOS_0) {
    tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);
}
```

This protects against zero, but it does not prove that the value is currently unused.

### Pending Response List Does Not Check Packet Identifier Collision

In `wolfMQTT-master/src/mqtt_client.c`, `MqttClient_RespList_Add` checks whether the exact `MqttPendResp` object pointer is already in the list:

```c
/* verify newResp is not already in the list */
for (tmpResp = client->firstPendResp;
     tmpResp != NULL;
     tmpResp = tmpResp->next)
{
    if (tmpResp == newResp) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_BAD_ARG);
    }
}
```

It then stores the Packet Identifier:

```c
newResp->packet_id = packet_id;
newResp->packet_type = packet_type;
newResp->packet_obj = packet_obj;
```

There is no equivalent check for an existing list entry with the same `packet_id`. Therefore, different pending response objects can be added with the same Packet Identifier.

### Publish Path Registers the Caller-Provided Packet Identifier

In `wolfMQTT-master/src/mqtt_client.c`, the QoS 1 and QoS 2 publish path registers a pending response using the current `publish->packet_id`:

```c
rc = MqttClient_RespList_Add(client, resp_type,
    publish->packet_id, &publish->pendResp, &publish->resp);
```

Because the pending response list does not reject a duplicate Packet Identifier, this path can register a second in-flight message with the same value.

### Broker-Side Packet Identifier Generation Only Skips Zero

In `wolfMQTT-master/src/mqtt_broker.c`, `BrokerNextPacketId` increments and wraps around zero:

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

This prevents zero from being assigned, but it does not consult an in-use set before reusing a value after wraparound.

## Runtime Reproduction

Two small reproducers were used.

### Pending List Reproducer

Source:

`wolfMQTT/101-150/repro_packet_id_inuse_collision.c`

Build and run:

```powershell
gcc -DHAVE_CONFIG_H -DWOLFMQTT_MULTITHREAD -IwolfMQTT/101-150 -IwolfMQTT-master wolfMQTT/101-150/repro_packet_id_inuse_collision.c wolfMQTT-master/src/mqtt_client.c wolfMQTT-master/src/mqtt_socket.c wolfMQTT-master/src/mqtt_packet.c -o wolfMQTT/101-150/repro_packet_id_inuse_collision.exe
wolfMQTT/101-150/repro_packet_id_inuse_collision.exe
```

Observed output:

```text
add first PUBLISH_ACK packet_id=7      rc=0
add SUBSCRIBE_ACK same packet_id=7     rc=0
add second PUBLISH_ACK same packet_id=7 rc=0
pending[0]: expected_type=4 packet_id=7
pending[1]: expected_type=9 packet_id=7
pending[2]: expected_type=4 packet_id=7
find PUBLISH_ACK packet_id=7 found=1 ptr_is_first=1
find SUBSCRIBE_ACK packet_id=7 found=1 ptr_is_subscribe=1
OBSERVED: duplicate in-use Packet Identifier entries were accepted
```

The first add registers a pending `PUBACK` for Packet Identifier `7`. The second add registers a pending `SUBACK` with the same Packet Identifier. The third add registers another pending `PUBACK` with the same Packet Identifier. All three calls return success.

### Public API Reproducer

Source:

`wolfMQTT/101-150/repro_packet_id_inuse_public_api.c`

Build and run:

```powershell
gcc -DHAVE_CONFIG_H -DWOLFMQTT_MULTITHREAD -DWOLFMQTT_NONBLOCK -IwolfMQTT/101-150 -IwolfMQTT-master wolfMQTT/101-150/repro_packet_id_inuse_public_api.c wolfMQTT-master/src/mqtt_client.c wolfMQTT-master/src/mqtt_socket.c wolfMQTT-master/src/mqtt_packet.c -o wolfMQTT/101-150/repro_packet_id_inuse_public_api.exe
wolfMQTT/101-150/repro_packet_id_inuse_public_api.exe
```

Observed output:

```text
first write-only publish packet_id=7  rc=-101 observed_packet_id=7
second write-only publish packet_id=7 rc=-101 observed_packet_id=7
writes=2 pending_entries_with_packet_id_7=2
OBSERVED: public API allowed two in-flight QoS1 PUBLISH packets with the same Packet Identifier
```

Here `-101` is `MQTT_CODE_CONTINUE`, which is expected in the non-blocking write-only flow while the acknowledgement is still pending. The important observation is that both packets were written with Packet Identifier `7`, and the pending response list retained two entries with that same value.

## Inconsistency

| Expected by MQTT | Observed in wolfMQTT |
|---|---|
| A new QoS 1 or QoS 2 packet must use a currently unused Packet Identifier. | A second new QoS 1 `PUBLISH` can be sent while the same Packet Identifier is already pending. |
| A Packet Identifier becomes reusable only after the corresponding acknowledgement flow completes. | The pending response list can contain multiple live entries with the same Packet Identifier. |
| Client-side and Server-side assignment both need to avoid currently in-use values. | Client pending registration and broker incrementing do not consult a complete in-use set. |

## Root Cause

The root cause is that wolfMQTT treats Packet Identifier uniqueness as mostly caller-managed state.

The implementation checks simple local properties:

| Area | Check present | Missing check |
|---|---|---|
| Encoder | Rejects zero for QoS 1 and QoS 2 `PUBLISH`. | Does not check whether the value is already in use. |
| Pending response list | Rejects reusing the same pending response object pointer. | Does not reject a different pending response object with the same Packet Identifier. |
| Client publish path | Registers the caller-provided Packet Identifier for acknowledgement matching. | Does not verify that the Packet Identifier is absent from the current in-flight set before sending. |
| Broker forwarding path | Increments Packet Identifier and skips zero. | Does not check whether the generated value is still in use after wraparound. |

## Impact

This is a protocol-state correctness issue with reliability and interoperability impact.

Potential effects:

| Effect | Description |
|---|---|
| Protocol non-compliance | wolfMQTT can send or track multiple new in-flight packets using the same Packet Identifier. |
| Acknowledgement ambiguity | An incoming acknowledgement may match one pending entry while another entry with the same Packet Identifier remains unresolved. |
| QoS delivery confusion | Duplicate Packet Identifier use can blur the distinction between a retransmission and a new application message. |
| Broker-side wraparound risk | If many messages are in flight and the broker-side counter wraps, a value can be reused without checking whether it is still active. |

This does not demonstrate memory corruption or code execution. The observed issue is best described as incomplete enforcement of MQTT Packet Identifier in-use uniqueness.

## Suggested Fix

wolfMQTT should maintain an in-use Packet Identifier set for each MQTT session direction that sends packets requiring Packet Identifiers.

At minimum:

| Requirement | Description |
|---|---|
| Allocate only unused values | New QoS 1 and QoS 2 sends should choose or accept only Packet Identifiers absent from the in-flight set. |
| Reject duplicate registration | `MqttClient_RespList_Add` should reject a second live entry with the same Packet Identifier when that identifier is not yet reusable. |
| Release on completion | The identifier should be released only after the required acknowledgement flow completes. |
| Handle wraparound safely | Broker-side generation should skip both zero and currently in-use values. |

