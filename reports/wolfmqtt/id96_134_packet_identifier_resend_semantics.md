# Packet Identifier Reuse Is Not Enforced for Re-sent Control Packets

## Summary

MQTT requires a re-sent Control Packet to use the same Packet Identifier that was used for the original send. wolfMQTT can preserve that value if the caller supplies the same `packet_id`, but the library does not enforce the rule itself.

In practice, the outbound path encodes the current `packet_id` stored in the caller-provided `MqttPublish` object. If the caller attempts to re-send the same logical `PUBLISH` but changes `packet_id`, wolfMQTT sends the changed value instead of rejecting it or restoring the original value.

## Standard Requirement

MQTT Version 3.1.1, Section 2.3.1, "Packet Identifier":

Online source: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html>

Original English requirement excerpt:

> MUST use the same Packet Identifier

The full sentence states that when a Client re-sends a particular Control Packet, subsequent re-sends of that packet must use the same Packet Identifier. The same section also states that the Packet Identifier is only available for reuse after the corresponding acknowledgement has been processed.

MQTT Version 3.1.1, Section 4.4, "Message delivery retry", also applies to reconnect recovery:

Original English requirement excerpt:

> using their original Packet Identifiers

That requirement applies when a Client reconnects with `CleanSession` set to `0`: both sides must re-send unacknowledged `PUBLISH` packets where `QoS > 0` and `PUBREL` packets using their original Packet Identifiers.

## Code Behavior

### Packet Encoding

`wolfMQTT-master/src/mqtt_packet.c` validates that a QoS 1 or QoS 2 `PUBLISH` has a non-zero Packet Identifier:

```c
if (publish->qos > MQTT_QOS_0) {
    if (publish->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }
    variable_len += MQTT_DATA_LEN_SIZE; /* For packet_id */
}
```

However, the encoder later writes whatever value is currently stored in `publish->packet_id`:

```c
if (publish->qos > MQTT_QOS_0) {
    tx_payload += MqttEncode_Num(tx_payload, publish->packet_id);
}
```

This means the encoder enforces "non-zero", but it does not know whether the packet is a first send or a re-send of a previous Control Packet.

### Publish Send Path

`wolfMQTT-master/src/mqtt_client.c` calls the packet encoder directly with the caller-provided `MqttPublish` object:

```c
rc = MqttEncode_Publish(client->tx_buf, client->tx_buf_len,
        publish, pubCb ? 1 : 0);
```

For QoS 1 or QoS 2, wolfMQTT waits for the acknowledgement that matches the same current `publish->packet_id`:

```c
rc = MqttClient_WaitType(client, &publish->resp, resp_type,
    publish->packet_id, client->cmd_timeout_ms);
```

The pending response list also stores the current Packet Identifier:

```c
newResp->packet_id = packet_id;
newResp->packet_type = packet_type;
newResp->packet_obj = packet_obj;
```

These paths track the response for the currently sent packet, but they do not preserve an immutable "original Packet Identifier" for a future re-send.

## Runtime Reproduction

A minimal runtime reproducer is available at:

`wolfMQTT/101-150/repro_packet_id_resend_semantics.c`

The reproducer uses a fake network layer that captures the bytes wolfMQTT writes. It does not require a real broker.

Build and run:

```powershell
gcc -DHAVE_CONFIG_H -IwolfMQTT/101-150 -IwolfMQTT-master wolfMQTT/101-150/repro_packet_id_resend_semantics.c wolfMQTT-master/src/mqtt_client.c wolfMQTT-master/src/mqtt_socket.c wolfMQTT-master/src/mqtt_packet.c -o wolfMQTT/101-150/repro_packet_id_resend_semantics.exe
wolfMQTT/101-150/repro_packet_id_resend_semantics.exe
```

Observed output:

```text
first publish rc=-7 observed_packet_id=7 writes_after_first=1 reads_after_first=1
second publish rc=-7 observed_packet_id=8
total writes=2 total reads=2
OBSERVED: resend-like second call used caller-supplied new Packet Identifier
```

The first send uses Packet Identifier `7`. The fake network read then returns a timeout, so the message is not acknowledged. The second call simulates an application-level re-send of the same logical message but changes `packet_id` to `8`. wolfMQTT writes a second `PUBLISH` containing Packet Identifier `8`.

If wolfMQTT enforced the re-send rule internally, the second call would either be rejected or the library would preserve the original Packet Identifier `7`.

## Inconsistency

| Expected by MQTT | Observed in wolfMQTT |
|---|---|
| A re-sent Control Packet must reuse the original Packet Identifier. | A second send uses the current caller-supplied `publish->packet_id`. |
| The original Packet Identifier remains unavailable until the acknowledgement is processed. | The library waits for the current send's acknowledgement, but does not maintain a durable re-send record. |
| Reconnect recovery for unacknowledged QoS traffic must use original Packet Identifiers. | The inspected send path does not provide an automatic resend queue that preserves original identifiers across retry decisions. |

The root cause is architectural: wolfMQTT exposes Packet Identifier ownership largely to the caller. The library validates the value and matches acknowledgements, but it does not maintain a higher-level resend state machine that binds a particular Control Packet to its original Packet Identifier across retransmission attempts.

## Impact

This is primarily a protocol reliability and state-consistency issue.

Potential effects include:

| Effect | Description |
|---|---|
| Protocol non-compliance | An application can re-send the same logical packet with a different Packet Identifier, and wolfMQTT will encode it. |
| QoS ambiguity | A receiver can treat the second packet as a new publication rather than a retransmission of the first one. |
| Duplicate delivery risk | For QoS 1 or QoS 2, changing Packet Identifier on re-send can interfere with duplicate detection and delivery semantics. |
| Reconnect recovery gap | Required recovery behavior for unacknowledged `PUBLISH` and `PUBREL` packets depends on preserving original identifiers. |


## Suggested Fix

wolfMQTT would need a resend-aware state layer for QoS 1 and QoS 2 Control Packets.

At minimum, such a layer should:

| Requirement | Description |
|---|---|
| Store original packet state | Preserve the original Packet Identifier, DUP state, packet type, topic, payload metadata, and QoS state until acknowledgement completes. |
| Detect re-send attempts | Distinguish a new packet from a re-send of a previous unacknowledged packet. |
| Enforce same Packet Identifier | Reject or override re-send attempts that try to use a different Packet Identifier. |
| Handle reconnect recovery | For `CleanSession = 0`, re-send unacknowledged `PUBLISH` and `PUBREL` packets with their original Packet Identifiers. |
| Add regression tests | Verify that re-sending a QoS 1 or QoS 2 packet cannot change its Packet Identifier before the corresponding acknowledgement is processed. |
