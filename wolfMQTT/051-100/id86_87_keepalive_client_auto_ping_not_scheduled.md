# ID86-87: Client Keep Alive PINGREQ Scheduling Is Not Built Into the Core Client

## Summary

Affected finding IDs: 86, 87.

MQTT 3.1.1 requires the Client to ensure that the interval between MQTT Control Packets sent to the Server does not exceed the negotiated Keep Alive value. If the Client has no other MQTT Control Packet to send before that interval expires, it must send a `PINGREQ`.

wolfMQTT supports the building blocks for this behavior: it encodes the Keep Alive field in `CONNECT`, provides `MqttClient_Ping()` / `MqttClient_Ping_ex()`, sends a valid `PINGREQ`, and waits for `PINGRESP`. However, the core client receive/wait loop does not automatically track the elapsed time since the last outbound Control Packet and does not automatically send `PINGREQ` before the Keep Alive interval expires.

The application or example code must schedule the ping itself. Therefore this is best classified as partial satisfaction, not as a complete absence of Keep Alive support.

Classification: partially satisfied.

## MQTT 3.1.1 Requirement

Source document:

```text
D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc
```

Relevant section:

- Section 3.1.2, CONNECT Variable Header, Keep Alive.
- Normative statement `[MQTT-3.1.2-23]`.
- Related server-side timeout statement `[MQTT-3.1.2-24]`.

Short original English excerpts:

```text
"does not exceed the Keep Alive value"
"Client MUST send a PINGREQ Packet"
"one and a half times"
```

Detailed English description of the standard requirement:

```text
The Keep Alive field is a 16-bit value measured in seconds. It defines the maximum permitted interval between the moment the Client finishes transmitting one MQTT Control Packet and the moment the Client starts transmitting the next MQTT Control Packet. This is a Client responsibility. If the Client is otherwise idle and has no normal application traffic or protocol packet to send, it must send a `PINGREQ` before the Keep Alive interval is exceeded.

The Client is allowed to send `PINGREQ` earlier than the Keep Alive deadline. This means a conforming implementation can use an application-level timer shorter than the Keep Alive value. What it must not do is wait until after the Keep Alive interval has already been exceeded and then treat that late ping as satisfying the requirement.

On the Server side, if the Keep Alive value is non-zero and the Server receives no Control Packet from the Client within 1.5 times the Keep Alive period, the Server must disconnect the Network Connection. That server-side rule is separate from the Client's earlier responsibility to avoid exceeding the Keep Alive interval in the first place.
```

## Expected Client Behavior

For a connected Client with non-zero Keep Alive:

| Situation | Expected behavior |
|---|---|
| Normal outbound MQTT Control Packets are sent within the Keep Alive interval | No extra `PINGREQ` is required |
| No outbound MQTT Control Packet has been sent and the Keep Alive deadline is approaching | Client sends `PINGREQ` before the interval is exceeded |
| Client sends `PINGREQ` and does not receive `PINGRESP` in a reasonable time | Client should close the Network Connection |
| Keep Alive is zero | The Keep Alive mechanism is disabled by the negotiated value |

The important timing point is that `PINGREQ` is a preventive keepalive packet. It should be scheduled before the negotiated interval is exceeded, not only after the MQTT Keep Alive requirement has already been violated.

## Code Evidence

### 1. CONNECT carries the Keep Alive value

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_Connect()`

Relevant line: `888`.

The encoder writes `mc_connect->keep_alive_sec` into the CONNECT variable header:

```text
MqttEncode_Num((byte*)&packet.keep_alive, mc_connect->keep_alive_sec)
```

The decoder also reads the field into `mc_connect->keep_alive_sec` at line `1005`.

This part satisfies the wire-format requirement for carrying the Keep Alive value.

### 2. The client provides an explicit Ping API

File: `wolfMQTT-master/src/mqtt_client.c`

Function: `MqttClient_Ping_ex()`

Relevant lines: `2572-2641`.

`MqttClient_Ping_ex()` performs the actual keepalive ping operation:

1. It calls `MqttEncode_Ping()` to encode a `PINGREQ`.
2. It writes the encoded packet using `MqttPacket_Write()`.
3. It waits for `MQTT_PACKET_TYPE_PING_RESP` using `MqttClient_WaitType()`.

The wrapper `MqttClient_Ping()` at line `2661` calls `MqttClient_Ping_ex()` using the client's internal ping object.

This means wolfMQTT can send a correct `PINGREQ`, but only when the caller explicitly invokes the ping API.

### 3. PINGREQ encoding is correct

File: `wolfMQTT-master/src/mqtt_packet.c`

Function: `MqttEncode_Ping()`

Relevant lines: `2355-2366`.

The encoder builds a `PINGREQ` packet with packet type `MQTT_PACKET_TYPE_PING_REQ` and no variable header or payload. The resulting fixed header is the expected MQTT bytes:

```text
C0 00
```

This confirms that the missing part is not packet encoding. The missing part is automatic scheduling.

### 4. The core wait API does not schedule Keep Alive

File: `wolfMQTT-master/src/mqtt_client.c`

Functions:

- `MqttClient_WaitMessage_ex()`, line `2874`.
- `MqttClient_WaitMessage()`, line `2880`.

`MqttClient_WaitMessage_ex()` simply calls:

```text
MqttClient_WaitType(client, msg, MQTT_PACKET_TYPE_ANY, 0, timeout_ms)
```

There is no check of the negotiated Keep Alive value, no tracking of the last outbound MQTT Control Packet time, and no automatic call to `MqttClient_Ping()` or `MqttClient_Ping_ex()` from this wait path.

### 5. Example code performs Keep Alive scheduling at application level

File: `wolfMQTT-master/examples/mqttclient/mqttclient.c`

Relevant lines: `554-600`.

The example read loop calls:

```text
MqttClient_WaitMessage(&mqttCtx->client, mqttCtx->cmd_timeout_ms)
```

When that application-defined wait period returns `MQTT_CODE_ERROR_TIMEOUT`, the example prints a keepalive message and explicitly calls:

```text
MqttClient_Ping_ex(&mqttCtx->client, &mqttCtx->ping)
```

This demonstrates the intended usage pattern in the examples: the application chooses a wait interval and calls the Ping API itself. This can be compliant if the application timeout is short enough to send `PINGREQ` before the MQTT Keep Alive interval is exceeded. It is not an automatic guarantee provided by the core client library.

### 6. Broker-side Keep Alive timeout is implemented separately

File: `wolfMQTT-master/src/mqtt_broker.c`

Relevant lines:

- `2737`: broker stores `mc.keep_alive_sec`.
- `3577`: broker responds to `PINGREQ` with `PINGRESP`.
- `3607-3611`: broker checks for 1.5 times Keep Alive timeout.

The broker/server side therefore has logic for the `[MQTT-3.1.2-24]` timeout rule. This does not remove the Client-side scheduling gap described by IDs 86 and 87.

## Local Probe Result

A temporary local probe was compiled against the wolfMQTT source tree to check whether `MqttClient_WaitMessage()` automatically sends `PINGREQ`.

Probe design:

1. The mock network `read` callback always returned `MQTT_CODE_ERROR_TIMEOUT`.
2. The mock network `write` callback counted writes and detected the `PINGREQ` bytes `C0 00`.
3. The probe first called `MqttClient_WaitMessage(&client, 1)`.
4. The probe then called `MqttClient_Ping(&client)` as a positive control.

Observed output:

```text
wait_rc=-7 read_calls=1 write_calls=0 pingreq_writes=0
manual_ping_rc=-7 read_calls=1 write_calls=1 pingreq_writes=1 first_write=C000
```

Interpretation:

| Call | Result |
|---|---|
| `MqttClient_WaitMessage()` | Timed out, but performed zero writes and sent no `PINGREQ` |
| `MqttClient_Ping()` | Wrote one packet, detected as `PINGREQ` bytes `C0 00` |

The probe confirms that the core wait path does not automatically send Keep Alive pings. The temporary probe source and executable were removed after the test.

## Why This Is an Inconsistency

The MQTT standard assigns the Keep Alive sending responsibility to the Client. For a complete client behavior, the implementation must ensure that the Client sends some MQTT Control Packet before the Keep Alive interval is exceeded. If no other Control Packet is sent, that packet must be `PINGREQ`.

wolfMQTT's core client library does not enforce this timing rule by itself:

1. It can advertise a Keep Alive value in CONNECT.
2. It can send `PINGREQ` and wait for `PINGRESP`.
3. It does not internally store or enforce a last-outbound-Control-Packet deadline.
4. It does not automatically call the Ping API from `MqttClient_WaitMessage()` when the connection is idle.
5. Example programs implement the scheduling externally by reacting to an application-level timeout.

The mismatch is therefore:

| Standard expectation | wolfMQTT core client behavior |
|---|---|
| Client ensures outbound Control Packet interval does not exceed Keep Alive | Core client exposes APIs, but does not automatically enforce the interval |
| Idle Client sends `PINGREQ` before the Keep Alive interval is exceeded | Application code must decide when to call `MqttClient_Ping()` / `MqttClient_Ping_ex()` |

This is a real gap if the evaluated target is the core wolfMQTT client library itself. It is less severe than a malformed-packet acceptance bug because wolfMQTT provides the required API primitives and the examples show how an application can schedule pings correctly.

## Classification Rationale

Recommended category:

```text
KeepAlive client auto-ping scheduling missing
```

Recommended status:

```text
partially satisfied
```

Recommended risk:

```text
medium
```

Reason:

IDs 86 and 87 describe the same underlying issue. wolfMQTT has Keep Alive support at the packet/API level, but the core client does not automatically maintain the Client-side Keep Alive obligation. A conforming application must schedule `MqttClient_Ping()` / `MqttClient_Ping_ex()` before the negotiated Keep Alive interval expires.

Suggested table wording:

```md
| 86 | 85 | partialsatisfied | medium | KeepAliveclient[non-English text removed] MqttClient_Ping/Ping_ex；[non-English text removed] PINGREQ。 |
| 87 | 86 | partialsatisfied | medium | KeepAliveclient[non-English text removed] MQTT Control Packet；[non-English text removed] Ping API。 |
```
