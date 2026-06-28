# SUBSCRIBE Requested QoS Options Are Accepted Without Strict Validation

## Summary

wolfMQTT accepts malformed MQTT 3.1.1 `SUBSCRIBE` packets whose Requested QoS/options byte is invalid.

Each topic entry in a `SUBSCRIBE` payload ends with one Requested QoS byte. In MQTT 3.1.1, only the low two bits encode the Requested QoS, and only values `0`, `1`, and `2` are valid. The upper six bits are reserved and must be zero. A server that receives a malformed `SUBSCRIBE` packet must reject it at the protocol boundary rather than silently normalizing it.

The current wolfMQTT decoder extracts only the low two bits:

```c
topic->qos = (MqttQoS)(options & 0x03);
```

As a result:

- `0x03` is accepted as `QoS=3`.
- `0xFC` is accepted as `QoS=0`.
- `0xFD` is accepted as `QoS=1`.

This is a receive-side protocol validation gap.

## Standard Reference

Source: [OASIS MQTT Version 3.1.1, online HTML](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html).

Relevant section: `3.8.3 Payload`, `SUBSCRIBE`.

The `SUBSCRIBE` payload is a sequence of topic entries. Each entry has:

```text
Topic Filter + Requested QoS byte
```

The Requested QoS byte is structured as follows:

| Bits | Meaning | MQTT 3.1.1 requirement |
|---|---|---|
| `7..2` | Reserved bits | Must be `0` |
| `1..0` | Requested QoS | Must be `0`, `1`, or `2` |

Short original English excerpts from Section `3.8.3`:

```text
"Reserved for future use"
"QoS is not 0,1 or 2"
"malformed and close the Network Connection"
```

Detailed English description of the requirement:

For every Topic Filter / Requested QoS pair in a `SUBSCRIBE` packet, the server must validate the full options byte. The lower two bits select the requested maximum QoS for that subscription. The valid values are `0`, `1`, and `2`. The bit pattern `11`, represented by value `3`, is not a valid Requested QoS in MQTT 3.1.1. The upper six bits are reserved for future protocol use and must be zero in MQTT 3.1.1 packets. If either condition is violated, the `SUBSCRIBE` packet is malformed and the server-side receive path should reject it and close the network connection.

## Expected Behavior

For MQTT 3.1.1 `SUBSCRIBE` decoding:

| Options byte | Meaning | Expected result |
|---:|---|---|
| `0x00` | Reserved bits zero, Requested QoS 0 | Accept |
| `0x01` | Reserved bits zero, Requested QoS 1 | Accept |
| `0x02` | Reserved bits zero, Requested QoS 2 | Accept |
| `0x03` | Requested QoS value 3 | Reject as malformed |
| `0xFC` | Reserved bits nonzero, Requested QoS bits 0 | Reject as malformed |
| `0xFD` | Reserved bits nonzero, Requested QoS bits 1 | Reject as malformed |
| `0xFE` | Reserved bits nonzero, Requested QoS bits 2 | Reject as malformed |
| `0xFF` | Reserved bits nonzero, Requested QoS bits 3 | Reject as malformed |

The key point is that validation must check both parts of the byte:

```text
(options & 0xFC) == 0
(options & 0x03) <= 2
```

Masking the byte with `0x03` and continuing is not equivalent to validating it.

## Code Evidence

### Decoder Masks the Options Byte

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Subscribe()`

The decoder reads the options byte and keeps only the low two bits:

```c
options = *rx_payload++;
topic->qos = (MqttQoS)(options & 0x03);
subscribe->topic_count++;
```

This has two consequences:

| Malformed byte | Current decoded value | Why this is wrong |
|---:|---:|---|
| `0x03` | `3` | Requested QoS `3` is invalid and should be rejected |
| `0xFC` | `0` | Reserved bits are nonzero but are discarded |
| `0xFD` | `1` | Reserved bits are nonzero but are discarded |

The function returns success after incrementing `topic_count`. There is no branch that rejects the malformed options byte.

### Broker Path Normalizes Instead of Rejecting

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Subscribe()`

After decoding, the broker caps values greater than QoS 2:

```c
MqttQoS topic_qos = sub.topics[i].qos;
MqttQoS granted_qos;

if (topic_qos > MQTT_QOS_2) {
    topic_qos = MQTT_QOS_2;
}
granted_qos = topic_qos;
```

This is useful for defensive normalization, but it is not the required protocol behavior for malformed input. A malformed Requested QoS/options byte should be rejected before the subscription is registered.

### Dispatch Does Not Enforce a Disconnect Branch for This Case

File: `wolfMQTT-master/src/mqtt_broker.c`

The broker dispatch calls the subscribe handler and ignores the return value:

```c
case MQTT_PACKET_TYPE_SUBSCRIBE:
    (void)BrokerHandle_Subscribe(bc, rc, broker);
    break;
```

If the decoder accepted a malformed options byte, the broker continues normally. Even if a future validation branch returned an error, this dispatch site would also need to enforce protocol-error handling consistently.

## Reproduction Test

Test file:

```text
wolfMQTT-master/tests/repro_subscribe_requested_qos_options.c
```

Build and run:

```powershell
cd wolfMQTT-master
gcc -I. -D_WOLFMQTT_VS_SETTINGS_ -DWOLFMQTT_BROKER src/mqtt_packet.c src/mqtt_socket.c src/mqtt_client.c tests/repro_subscribe_requested_qos_options.c -o tests/repro_subscribe_requested_qos_options.exe
.\tests\repro_subscribe_requested_qos_options.exe
```

Test packets:

| Packet bytes | Meaning | Expected |
|---|---|---|
| `82 06 00 01 00 01 61 00` | Valid `SUBSCRIBE`, topic `a`, Requested QoS 0 | Accept |
| `82 06 00 01 00 01 61 03` | Requested QoS 3 | Reject |
| `82 06 00 01 00 01 61 FC` | Reserved bits nonzero, low bits QoS 0 | Reject |
| `82 06 00 01 00 01 61 FD` | Reserved bits nonzero, low bits QoS 1 | Reject |

Observed output:

```text
valid requested qos 0              rc=8 topic_count=1 decoded_qos=0 expected=accept observed=accept
invalid requested qos 3            rc=8 topic_count=1 decoded_qos=3 expected=reject observed=accept
invalid reserved bits qos 0        rc=8 topic_count=1 decoded_qos=0 expected=reject observed=accept
invalid reserved bits qos 1        rc=8 topic_count=1 decoded_qos=1 expected=reject observed=accept
repro verdict: issue reproduced: invalid SUBSCRIBE Requested QoS/options were accepted
```

The return value `rc=8` is the decoded packet length, which indicates successful decode. The malformed packets were therefore accepted.

## Inconsistency

| Standard requirement | wolfMQTT behavior |
|---|---|
| Requested QoS must be one of `0`, `1`, or `2` | `0x03` is accepted and decoded as `QoS=3` |
| Reserved bits in the Requested QoS byte must be zero | High six bits are masked away with `options & 0x03` |
| Malformed `SUBSCRIBE` should be rejected at the receive boundary | Decoder returns success and broker continues processing |
| Protocol error handling should stop normal subscription registration | Broker subscribe dispatch does not enforce a disconnect/error branch for this malformed input |

## Root Cause

The implementation treats the options byte as a source from which QoS can be extracted, but the standard treats it as a constrained protocol field that must be validated as a whole.

The missing checks are:

```c
if ((options & 0xFC) != 0) {
    /* reserved bits violation */
}

if ((options & 0x03) > MQTT_QOS_2) {
    /* invalid Requested QoS */
}
```

Without these checks, malformed `SUBSCRIBE` packets can pass through decode and reach broker subscription handling.

## Suggested Fix Direction

Add strict validation in `MqttDecode_Subscribe()` immediately after reading the options byte:

```c
options = *rx_payload++;
if ((options & 0xFC) != 0 || (options & 0x03) > MQTT_QOS_2) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_MALFORMED_DATA);
}
topic->qos = (MqttQoS)(options & 0x03);
```

Then ensure the broker dispatch path treats a subscribe handler error as a protocol error and closes the client connection, consistent with the malformed-packet handling required by MQTT 3.1.1.

