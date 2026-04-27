# ID183-186: PUBLISH QoS Bits 11 Are Accepted Instead of Rejected

## Summary

Affected finding IDs: 183, 184, 185, 186.

MQTT 3.1.1 forbids a PUBLISH packet whose QoS bits are both set to `1`. That bit pattern is `11`, which is decoded as `QoS=3`. The receiver must treat such a packet as a protocol violation and close the network connection.

wolfMQTT currently extracts the QoS bits from the fixed header, stores the value in `publish->qos`, and continues decoding when the value is `3`. A local probe confirmed that a PUBLISH packet with first byte `0x36` is decoded successfully as `qos=3`.

Classification: not satisfied.

## MQTT 3.1.1 Requirement

Source document:

```text
D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc
```

Relevant section:

- Section 3.3.1, PUBLISH fixed header, QoS.
- Normative statement `[MQTT-3.3.1-4]`.

Short original English excerpts:

```text
"MUST NOT have both QoS bits set to 1"
"MUST close the Network Connection"
```

Detailed English description of the standard requirement:

In the PUBLISH fixed header, bits 2 and 1 encode the PUBLISH QoS level. MQTT 3.1.1 defines three legal QoS levels for PUBLISH:

| QoS bits | QoS value | Meaning |
|---|---:|---|
| `00` | 0 | At most once delivery |
| `01` | 1 | At least once delivery |
| `10` | 2 | Exactly once delivery |
| `11` | reserved | invalid for MQTT 3.1.1 PUBLISH |

Therefore, if a Client or Server receives a PUBLISH packet whose QoS bits are `11`, the packet is malformed at the protocol level. The expected behavior is not to treat it as a higher QoS level. The receiver must reject it and close the network connection.

## Expected Behavior

For MQTT 3.1.1 PUBLISH receive-side decoding:

| First byte example | Meaning | Expected result |
|---|---|---|
| `0x30` | PUBLISH, QoS bits `00` | valid QoS 0 PUBLISH |
| `0x32` | PUBLISH, QoS bits `01` | valid QoS 1 PUBLISH |
| `0x34` | PUBLISH, QoS bits `10` | valid QoS 2 PUBLISH |
| `0x36` | PUBLISH, QoS bits `11` | malformed, close connection |

Checking only that the packet type is PUBLISH is insufficient. The PUBLISH-specific QoS bits must also be checked for the forbidden `11` value.

## Code Evidence

### 1. QoS value 3 is represented in the enum

File: `wolfMQTT-master/wolfmqtt/mqtt_packet.h`

Relevant lines: `181-184`.

The enum defines `MQTT_QOS_3 = 3`, and the comment marks it as reserved for MQTT:

```text
MQTT_QOS_3 = 3
MQTT - Reserved - must not be used
```

This is not itself wrong, because the same enum is also used by MQTT-SN. But for MQTT 3.1.1 PUBLISH receive-side decoding, this value must be rejected.

### 2. Fixed-header decoding extracts QoS but does not validate it

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_FixedHeader()`

Relevant lines: `185-215`.

The decoder first validates only the packet type:

```text
MQTT_PACKET_TYPE_GET(header->type_flags) == type
```

Then it extracts the QoS bits through `MQTT_PACKET_FLAGS_GET_QOS(header->type_flags)` and stores the result in the caller-provided QoS output. There is no check here that rejects `MQTT_QOS_3` for PUBLISH.

### 3. PUBLISH decoding accepts the extracted QoS value

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Publish()`

Relevant lines: `1413-1454`.

`MqttDecode_Publish()` calls `MqttDecode_FixedHeader()` with `&publish->qos`, so the raw QoS bits are copied into the decoded PUBLISH object. After that, the function only checks whether the QoS is greater than zero:

```text
publish->qos > MQTT_QOS_0
```

That condition is true for `MQTT_QOS_3`. As a result, the decoder proceeds to read a Packet Identifier and continues normal parsing instead of returning a malformed-packet error.

### 4. Broker PUBLISH handling relies on this decoder

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Publish()`

Relevant lines: `3190-3210`.

The broker receives PUBLISH packets by calling:

```text
MqttDecode_Publish(bc->rx_buf, rx_len, &pub)
```

It only treats the packet as invalid if `MqttDecode_Publish()` returns a negative error. Because the decoder accepts QoS bits `11`, this broker path does not enforce the required malformed + close behavior for this violation.

### 5. Client receive path also uses the same decoder

File: `wolfMQTT-master/src/mqtt_client.c`

Function: `MqttClient_DecodePacket()`

Relevant lines: `617-695`.

The client receive path derives `packet_qos` directly from the fixed header and decodes incoming PUBLISH packets using `MqttDecode_Publish()`. Therefore, the same missing QoS=3 rejection affects both receiving roles that use this shared packet decoder.

## Local Probe Result

A minimal C probe was compiled against the local wolfMQTT sources. The probe passed this packet to `MqttDecode_Publish()`:

```text
36 05 00 01 61 00 01
```

Packet meaning:

| Byte(s) | Meaning |
|---|---|
| `0x36` | PUBLISH, QoS bits `11`, retain `0` |
| `0x05` | remaining length 5 |
| `0x00 0x01 0x61` | topic name `a` |
| `0x00 0x01` | packet identifier 1 |

Observed output:

```text
rc=7 qos=3 packet_id=1 topic_len=1
```

This proves that the decoder returned success and populated `publish->qos` with `3`. The expected behavior under `[MQTT-3.3.1-4]` is an error that leads to closing the network connection.

The temporary probe source and executable were removed after the test.

## Why This Is an Inconsistency

The standard requires a receiver to reject PUBLISH QoS bits `11`. wolfMQTT instead treats the bit pattern as an ordinary decoded enum value:

1. The fixed-header decoder extracts QoS bits without validating the forbidden `11` combination.
2. The PUBLISH decoder treats any QoS value greater than zero as a reason to read a Packet Identifier.
3. The broker and client receive paths depend on the decoder returning a negative error to identify malformed packets.
4. The tested malformed packet returned success, so no protocol-level rejection or connection close is triggered by this decoder path.

The mismatch is therefore real: MQTT requires "QoS bits `11` => malformed + close", while wolfMQTT currently performs "QoS bits `11` => decoded as `MQTT_QOS_3` and parsed successfully".

## Classification Rationale

Recommended category:

```text
PUBLISH QoS bits illegal value validation missing
```

Recommended status:

```text
not satisfied
```

Reason:

IDs 183-186 describe the same underlying defect. The implementation lacks receive-side validation for the reserved PUBLISH QoS bit pattern `11`, so an invalid MQTT 3.1.1 PUBLISH packet can enter the normal decode path instead of causing the required malformed-packet rejection and network connection close.
