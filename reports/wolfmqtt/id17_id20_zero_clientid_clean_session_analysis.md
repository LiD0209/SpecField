# Zero-Length ClientId Is Not Bound to CleanSession

## Summary

This document shows that wolfMQTT does not consistently enforce the MQTT 3.1.1 rule tying a zero-length ClientId to `CleanSession=1`. A zero-length ClientId with `CleanSession=0` can reach the accepted connection path instead of receiving CONNACK `0x02` followed by connection close, and some build paths can assign an automatic ClientId to that invalid combination.

## English Standard Text

The relevant MQTT 3.1.1 clauses are in the `Client Identifier` section.

Short original English excerpts:

```text
"zero-byte ClientId"
"MUST also set CleanSession to 1"
"CONNACK return code 0x02"
```

Relevant normative requirements:

- `[MQTT-3.1.3-6]`: A server may allow a zero-byte ClientId, but if it does, it must assign a unique ClientId and process the CONNECT as if that ID had been supplied by the client.
- `[MQTT-3.1.3-7]`: If a client supplies a zero-byte ClientId, the client must set `CleanSession` to `1`.
- `[MQTT-3.1.3-8]`: If a client supplies a zero-byte ClientId with `CleanSession=0`, the server must respond with CONNACK return code `0x02` (`Identifier rejected`) and then close the network connection.
- `[MQTT-3.1.3-9]`: If the server rejects the ClientId, it must respond with CONNACK return code `0x02` and then close the network connection.

Therefore, MQTT 3.1.1 allows an empty ClientId only as a special case, and that special case is tied to `CleanSession=1`. Empty ClientId plus `CleanSession=0` is not an acceptable persistent-session request.

## Code Description

### 1. CONNECT decoding extracts fields but does not enforce the linkage

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttDecode_Connect()`

Relevant behavior:

```c
mc_connect->clean_session =
    (packet.flags & MQTT_CONNECT_FLAG_CLEAN_SESSION) ? 1 : 0;
```

The decoder later parses the ClientId string:

```c
tmp = MqttDecode_String(rx_payload, &mc_connect->client_id, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

This function decodes `CleanSession` and `ClientId`, but it does not check:

```c
if (client_id_len == 0 && clean_session == 0) reject;
```

So the protocol constraint from `[MQTT-3.1.3-7]` / `[MQTT-3.1.3-8]` is not enforced at decode time.

### 2. Broker stores an empty ClientId without rejecting the connection

File: `wolfMQTT-master/src/mqtt_broker.c`

Function: `BrokerHandle_Connect()`

Relevant behavior:

```c
if (mc.client_id) {
    word16 id_len = 0;
    if (MqttDecode_Num((byte*)mc.client_id - MQTT_DATA_LEN_SIZE,
            &id_len, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        BROKER_STORE_STR(bc->client_id, mc.client_id, id_len,
            BROKER_MAX_CLIENT_ID_LEN);
    }
}
```

For a zero-length ClientId, `id_len` is `0`. The broker stores that value and continues.

The broker then records the clean-session bit:

```c
bc->clean_session = mc.clean_session;
```

But there is no check immediately after this assignment to reject:

```c
empty ClientId && clean_session == 0
```

As a result, the connection reaches later CONNECT processing instead of being rejected with `0x02`.

### 3. The normal CONNACK path accepts the connection

File: `wolfMQTT-master/src/mqtt_broker.c`

The default CONNACK state is accepted:

```c
ack.flags = 0;
ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
```

The function only returns `0` to force disconnect when the return code is not accepted:

```c
if (ack.return_code != MQTT_CONNECT_ACK_CODE_ACCEPTED) {
    return 0;
}
return rc;
```

Because there is no branch that sets:

```c
ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_ID;
```

for zero-length ClientId plus `clean_session=0`, the broker sends `CONNACK 0x00` and the caller marks the client as connected.

### 4. MQTT v5/static-memory path can assign an ID even when clean_session is 0

File: `wolfMQTT-master/src/mqtt_broker.c`

The MQTT v5 path has logic to assign an ID when the broker considers the ClientId absent:

```c
if (!BROKER_STR_VALID(bc->client_id)) {
    char auto_id[32];
    int id_len = XSNPRINTF(auto_id, (int)sizeof(auto_id),
        "auto-%04x", broker->next_packet_id++);
    ...
    BROKER_STORE_STR(bc->client_id, auto_id, (word16)id_len,
        BROKER_MAX_CLIENT_ID_LEN);
}
```

In the `WOLFMQTT_STATIC_MEMORY` build, `BROKER_STR_VALID(s)` checks whether the first character is non-zero. An empty ClientId is therefore treated as absent, and this branch can generate an assigned ID such as `auto-0001`.

The problem is that this branch is not guarded by:

```c
mc.clean_session == 1
```

So a client using zero-length ClientId with `clean_session=0` can still be accepted and assigned an ID in this configuration.

## Reproduction Result

The issue was verified with a real broker run and raw CONNECT packets.

### Dynamic-memory build

Test case:

```text
MQTT 3.1.1 CONNECT, zero-length ClientId, CleanSession=0
```

Observed result:

```json
{"case":"mqtt311_emptyid_clean0","connack_hex":"20020000","return_or_reason_code":0,"ping_resp_hex":"d000","alive_after_connack":true}
```

Meaning:

- `connack_hex = 20 02 00 00`
- CONNACK return code is `0x00` (`Accepted`)
- The connection remains alive and responds to `PINGREQ`

Expected result from MQTT 3.1.1:

```text
CONNACK return code 0x02, then close the network connection.
```

### Static-memory + MQTT v5 build

Test case:

```text
MQTT 5 CONNECT, zero-length ClientId, CleanSession=0
```

Observed result:

```json
{"case":"mqtt5_emptyid_clean0","return_or_reason_code":0,"assigned_client_id":"auto-0001","alive_after_connack":true}
```

Meaning:

- The broker accepts the connection.
- The broker assigns a generated ClientId.
- The connection remains alive.

This confirms the specific invalid-assignment behavior: a path exists where the implementation accepts the invalid combination and assigns an ID instead of rejecting it.

## Issue Mapping

| Issue aspect | Why it is real |
|---|---|
| Empty ClientId processing | `MqttDecode_Connect()` and `BrokerHandle_Connect()` allow an empty ClientId with `clean_session=0` to continue into normal processing. |
| Missing reject path | The required `0x02 + close` path is not executed; in the static-memory MQTT v5 path, the broker can assign `auto-xxxx` instead. |
| CleanSession linkage | The rule "zero-byte ClientId requires CleanSession=1" is not enforced in the decoder or broker handler. |
| Server-side rejection | There is no explicit server-side branch that rejects `empty ClientId && clean_session == 0` with `MQTT_CONNECT_ACK_CODE_REFUSED_ID` and closes the connection. |

## Inconsistency Reason

The standard treats zero-length ClientId as a special case:

- It may be accepted only under the required CleanSession condition.
- If the condition is violated, the server must reject with `0x02` and close.

wolfMQTT currently handles the pieces separately:

- It decodes `CleanSession`.
- It decodes and stores `ClientId`.
- It has some ClientId rejection paths, such as excessive length.
- It has an ID-assignment path for empty ClientId in MQTT v5/static-memory builds.

But it does not combine the two fields into the required validation:

```c
if (client_id_len == 0 && mc.clean_session == 0) {
    ack.return_code = MQTT_CONNECT_ACK_CODE_REFUSED_ID;
    goto send_connack;
}
```

Because that linkage is missing, an invalid persistent-session CONNECT request can be accepted as a normal connection.

## Final Conclusion

The reported issue is real.

The empty-ClientId issues are all manifestations of the same missing validation: zero-length ClientId is not bound to `CleanSession=1`, and the required `CONNACK 0x02 + close` rejection path is absent for `CleanSession=0`.

Risk impact: a client can request a persistent session without providing a stable ClientId, which violates MQTT 3.1.1 session semantics and can lead to inconsistent session handling.
