# Packet Identifier Zero Acceptance on Receive Paths

## Summary

wolfMQTT enforces the non-zero Packet Identifier rule when encoding outbound `PUBLISH`, `SUBSCRIBE`, and `UNSUBSCRIBE` packets, but the matching receive-side decode paths accept `packet_id = 0`.

This means a peer can send malformed MQTT Control Packets that should be rejected by the receiver, but wolfMQTT parses them successfully and exposes `packet_id = 0` to upper-layer handling.

## Standard Requirement

MQTT Version 3.1.1, Section 2.3.1, "Packet Identifier":

Online source: <https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.pdf>

Original English requirement:

> SUBSCRIBE, UNSUBSCRIBE, and PUBLISH (in cases where QoS > 0) Control Packets MUST contain a non-zero 16-bit Packet Identifier [MQTT-2.3.1-1].

The same section also states that a QoS 0 `PUBLISH` must not contain a Packet Identifier. Therefore, the valid relationship is:

| Control Packet | Packet Identifier requirement |
|---|---|
| `PUBLISH` with `QoS = 0` | Must be absent |
| `PUBLISH` with `QoS > 0` | Must be present and non-zero |
| `SUBSCRIBE` | Must be present and non-zero |
| `UNSUBSCRIBE` | Must be present and non-zero |

For `PUBLISH`, this is a QoS-dependent rule rather than a standalone Packet Identifier rule. The receiver must validate the combination of the fixed-header QoS bits and the variable-header Packet Identifier:

| Received `PUBLISH` state | Expected receiver behavior |
|---|---|
| `QoS = 0` and no Packet Identifier | Accept the Packet Identifier relationship |
| `QoS > 0` and non-zero Packet Identifier | Accept the Packet Identifier relationship |
| `QoS > 0` and `packet_id = 0` | Reject the packet |

## Code Behavior

### Encoding Side

The outbound encoding paths reject zero Packet Identifiers.

In `wolfMQTT-master/src/mqtt_packet.c`, `MqttEncode_Publish` rejects `packet_id == 0` when `publish->qos > MQTT_QOS_0`:

```c
if (publish->qos > MQTT_QOS_0) {
    if (publish->packet_id == 0) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
    }
    variable_len += MQTT_DATA_LEN_SIZE; /* For packet_id */
}
```

`MqttEncode_Subscribe` also rejects zero:

```c
/* [MQTT-2.3.1-1] SUBSCRIBE packets require a non-zero packet identifier */
if (subscribe->packet_id == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
}
```

`MqttEncode_Unsubscribe` does the same:

```c
/* [MQTT-2.3.1-1] UNSUBSCRIBE packets require a non-zero packet identifier */
if (unsubscribe->packet_id == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
}
```

So wolfMQTT's own transmit path is aligned with the standard for this rule.

### Decoding Side

The inbound decode paths read the Packet Identifier but do not reject zero.

`MqttDecode_Publish` reads the Packet Identifier for `QoS > 0`:

```c
if (publish->qos > MQTT_QOS_0) {
    int tmp;
    if (rx_payload - rx_buf + MQTT_DATA_LEN_SIZE > rx_buf_len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    tmp = MqttDecode_Num(rx_payload, &publish->packet_id,
            (word32)(rx_buf_len - (rx_payload - rx_buf)));
    if (tmp < 0) {
        return tmp;
    }
    variable_len += tmp;
    ...
}
```

There is no equivalent check:

```c
if (publish->packet_id == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
}
```

This means the decode path observes the QoS-to-Packet-Identifier relationship only structurally: if `QoS > 0`, it consumes two bytes as the Packet Identifier field. It does not validate the value-level requirement that those two bytes must not be `0x0000`.

`MqttDecode_Subscribe` similarly decodes `subscribe->packet_id` and advances the input pointer without validating non-zero:

```c
tmp = MqttDecode_Num(rx_payload, &subscribe->packet_id,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
if (tmp < 0) {
    return tmp;
}
rx_payload += tmp;
```

`MqttDecode_Unsubscribe` follows the same pattern:

```c
tmp = MqttDecode_Num(rx_payload, &unsubscribe->packet_id,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
if (tmp < 0) {
    return tmp;
}
rx_payload += tmp;
```

## Reproduction

A small decode-only reproducer is available at:

`wolfMQTT/101-150/repro_packet_id_zero_decode.c`

Build and run:

```powershell
gcc -DHAVE_CONFIG_H -IwolfMQTT/101-150 -IwolfMQTT-master wolfMQTT/101-150/repro_packet_id_zero_decode.c wolfMQTT-master/src/mqtt_packet.c -o wolfMQTT/101-150/repro_packet_id_zero_decode.exe
wolfMQTT/101-150/repro_packet_id_zero_decode.exe
```

Observed output:

```text
decode PUBLISH QoS1 packet_id=0    rc=7 packet_id=0 expected=-5 OBSERVED
decode PUBLISH QoS1 packet_id=1    rc=7 packet_id=1 expected=7 PASS
decode SUBSCRIBE packet_id=0       rc=8 packet_id=0 expected=-5 OBSERVED
decode SUBSCRIBE packet_id=1       rc=8 packet_id=1 expected=8 PASS
decode UNSUBSCRIBE packet_id=0     rc=7 packet_id=0 expected=-5 OBSERVED
decode UNSUBSCRIBE packet_id=1     rc=7 packet_id=1 expected=7 PASS
```

`MQTT_CODE_ERROR_PACKET_ID` is `-5`. The zero Packet Identifier cases should return that error, but instead they return the packet length, which indicates successful decoding.

## Inconsistency

The inconsistency is between outbound validation and inbound validation:

| Path | Behavior |
|---|---|
| Encode `PUBLISH QoS > 0` | Rejects `packet_id = 0` |
| Decode `PUBLISH QoS > 0` | Accepts `packet_id = 0` |
| Encode `SUBSCRIBE` | Rejects `packet_id = 0` |
| Decode `SUBSCRIBE` | Accepts `packet_id = 0` |
| Encode `UNSUBSCRIBE` | Rejects `packet_id = 0` |
| Decode `UNSUBSCRIBE` | Accepts `packet_id = 0` |

For `PUBLISH`, the missing validation can also be stated as an incomplete QoS linkage check:

| Rule component | Encode path | Decode path |
|---|---|---|
| `QoS = 0` means no Packet Identifier field | Encodes no Packet Identifier | Decodes no Packet Identifier |
| `QoS > 0` means Packet Identifier field is present | Encodes the field | Decodes the field |
| `QoS > 0` means Packet Identifier value is non-zero | Rejects zero | Accepts zero |

The root cause is that `MqttDecode_Num` only decodes a two-byte integer. It treats `0x0000` as a valid numeric value, which is reasonable for a generic number decoder. The protocol-specific non-zero validation needs to be performed by the packet-specific decode functions, but those checks are missing.

## Impact

This is a protocol input-validation issue. A remote peer can send malformed MQTT packets with `packet_id = 0` and have them parsed as valid by wolfMQTT.

Likely effects include:

| Effect | Description |
|---|---|
| Protocol non-compliance | The receiver accepts packets that MQTT 3.1.1 requires to use a non-zero Packet Identifier. |
| State inconsistency | `0` can be confused with an absent or unset Packet Identifier in later processing. |
| Invalid acknowledgements | The implementation may generate acknowledgements using `packet_id = 0`. |
| Robustness risk | A broker exposed to untrusted clients may process malformed traffic instead of rejecting it early. |

This does not by itself demonstrate memory corruption or code execution. The security significance is best described as malformed packet acceptance and receiver-side state validation weakness.

## Suggested Fix

Add packet-specific non-zero checks immediately after decoding Packet Identifier fields:

```c
if (publish->packet_id == 0) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_PACKET_ID);
}
```

The same pattern should be applied to `MqttDecode_Subscribe` and `MqttDecode_Unsubscribe` after `MqttDecode_Num` succeeds.

Regression tests should include:

| Test case | Expected result |
|---|---|
| `PUBLISH QoS1` with Packet Identifier `0x0000` | `MQTT_CODE_ERROR_PACKET_ID` |
| `PUBLISH QoS2` with Packet Identifier `0x0000` | `MQTT_CODE_ERROR_PACKET_ID` |
| `PUBLISH QoS1` with Packet Identifier `0x0001` | Successful decode |
| `PUBLISH QoS2` with Packet Identifier `0x0001` | Successful decode |
| `SUBSCRIBE` with Packet Identifier `0x0000` | `MQTT_CODE_ERROR_PACKET_ID` |
| `UNSUBSCRIBE` with Packet Identifier `0x0000` | `MQTT_CODE_ERROR_PACKET_ID` |
| Valid non-zero Packet Identifier cases | Successful decode |
