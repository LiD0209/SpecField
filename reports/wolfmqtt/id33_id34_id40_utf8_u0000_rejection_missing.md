# U+0000 Rejection Is Missing and Leads to Broker Security Confusion

## Summary

wolfMQTT does not reject `U+0000` in MQTT UTF-8 string fields. This is already a protocol violation, but in the built-in broker it goes further: the decoded bytes are later copied into NUL-terminated C strings and then compared with `strlen`/`strcmp` style logic. As a result, values such as `admin\x00evil` can be interpreted as `admin` by later broker logic.

This creates security-significant behavior, not only a compliance gap.

Confirmed effects in the stock broker:

- username/password authentication bypass with `user\x00suffix`
- ClientId collision and session takeover with `client\x00suffix`
- topic routing confusion where `topic\x00hidden` is forwarded as `topic`

## Why This Matters

The core problem is semantic disagreement between layers:

- the MQTT decoder treats UTF-8 strings as length-prefixed byte sequences
- later broker code treats stored values as ordinary C strings
- `U+0000` splits those two views of the same value

So the MQTT layer may accept a full value like `admin\x00evil`, while later code sees only `admin`. That opens the door to identity confusion, session confusion, routing confusion, and misleading logs.

## Standard Requirement

The relevant MQTT 3.1.1 rule is Section `1.5.3 UTF-8 encoded strings`, clause `[MQTT-1.5.3-2]`.

```text
A UTF-8 encoded string MUST NOT include an encoding of the null character
U+0000.

If a receiver (Server or Client) receives a Control Packet containing U+0000
it MUST close the Network Connection [MQTT-1.5.3-2].
```

There is also a topic-specific rule in Section `4.7.3 Topic semantic and usage`, clause `[MQTT-4.7.3-2]`.

```text
Topic Names and Topic Filters MUST NOT include the null character
(Unicode U+0000) [MQTT-4.7.3-2].
```

The ClientId rule follows as well because `[MQTT-3.1.3-4]` requires ClientId to be a UTF-8 encoded string defined by Section `1.5.3`.

Required receiver behavior is clear: reject the packet and close the network connection. Silent acceptance is not allowed.

## Root Cause

### 1. Shared decoder preserves raw `0x00`

File: `wolfMQTT-master/src/mqtt_packet.c`  
Function: `MqttDecode_String()`

```c
len = MqttDecode_Num(buf, &str_len, buf_len);
if (len < 0) {
    return len;
}
if ((word32)str_len > buf_len - (word32)len) {
    return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
}
buf += len;
if (pstr) {
    *pstr = (char*)buf;
}
return len + str_len;
```

This function checks only the MQTT length prefix and bounds. It does not scan for `U+0000`, malformed UTF-8, or forbidden code points.

### 2. CONNECT fields are decoded without `U+0000` validation

File: `wolfMQTT-master/src/mqtt_packet.c`  
Function: `MqttDecode_Connect()`

Relevant calls:

```c
tmp = MqttDecode_String(rx_payload, &mc_connect->client_id, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
...
tmp = MqttDecode_String(rx_payload, &mc_connect->username, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
...
tmp = MqttDecode_String(rx_payload, &mc_connect->password, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
```

### 3. Broker stores those values as C strings

File: `wolfMQTT-master/src/mqtt_broker.c`  
Functions: `BrokerStore_String()`, `BrokerHandle_Connect()`

Relevant behavior:

```c
*dst_ptr = (char*)WOLFMQTT_MALLOC(src_len + 1);
if (*dst_ptr != NULL) {
    XMEMCPY(*dst_ptr, src, src_len);
    (*dst_ptr)[src_len] = '\0';
}
```

The broker preserves the original bytes, including embedded NUL, but also appends a terminator at the end. That means later `strlen`/`strcmp` based logic will stop at the first embedded `\0`.

### 4. Later broker logic uses `XSTRLEN` and `XSTRCMP`

File: `wolfMQTT-master/src/mqtt_broker.c`

Examples:

- auth comparison in `BrokerStrCompare()`
- duplicate ClientId detection in `BrokerClient_FindByClientId()`
- subscription reassociation and removal by ClientId
- topic matching in `BrokerTopicMatch()`

That is the step where `admin\x00evil` becomes equivalent to `admin`.

## Confirmed Security Impact

### 1. Authentication bypass

When broker auth is configured as `user` / `pass`, the broker rejects a wrong username like `userX`, but accepts:

- username: `user\x00evil`
- password: `pass\x00evil`

Reason:

- the MQTT layer accepts the full byte sequence
- broker auth later compares with `XSTRLEN`-derived lengths
- both stored values are effectively treated as `user` and `pass`

This is a real auth bypass in the stock broker, not just a hypothetical risk in an external plugin.

### 2. ClientId collision and session takeover

If one client connects as `admin`, a second client connecting as `admin\x00evil` is treated as having the same ClientId. The broker disconnects the original `admin` session as a duplicate and accepts the new one.

Reason:

- duplicate ClientId detection uses `XSTRCMP`
- embedded NUL truncates the later comparison view

This gives an attacker a practical way to kick a victim session off the broker and take over the logical ClientId.

### 3. Topic routing confusion

If a subscriber registers `sensor`, and another client publishes to `sensor\x00secret`, the broker forwards the message as if it were published to `sensor`.

Reason:

- topic copies are turned into NUL-terminated strings
- later topic matching runs with C-string semantics

This is message routing confusion. In a deployment that uses topic names as a trust boundary, it can become an authorization or isolation problem.

## What Was Tested

The reproduction package confirms the following three cases:

1. `auth_bypass_nul_suffix`
   - negative control: `userX` is rejected
   - attack case: `user\x00evil` and `pass\x00evil` are accepted

2. `clientid_collision_nul_suffix`
   - victim connects as `admin`
   - attacker connects as `admin\x00evil`
   - broker disconnects the victim as a duplicate ClientId

3. `topic_confusion_publish_nul_suffix`
   - subscriber subscribes to `sensor`
   - publisher sends to `sensor\x00secret`
   - subscriber receives a PUBLISH whose topic is `sensor`

## Example Observed Results

Representative observations from local reproduction:

```text
wrong_plain -> CONNACK 20020004
wrong_nul_prefix_match -> CONNACK 20020000

victim admin -> CONNACK 20020000
attacker admin\x00evil -> CONNACK 20020000
broker log: duplicate client_id=admin, disconnecting old sock=4

subscriber filter sensor
publisher topic sensor\x00secret
subscriber received topic sensor
```

These results show that the issue is not limited to packet acceptance. The broker performs security-relevant decisions on the truncated interpretation.

## Deployment Notes

This document only claims what was confirmed in the stock wolfMQTT broker.

- I did not rely on any external ACL plugin to demonstrate impact.
- I did not need custom application code to demonstrate impact.
- If an application, plugin, or audit layer also uses C-string logic, risk can be higher.

So the issue should be reported as a real security bug even without additional ACL assumptions.

## Reproduction Package

The bundled reproduction files are in:

- `wolfMQTT/001-050/repro_id33_34_40_u0000_security/u0000_security_repro.py`
- `wolfMQTT/001-050/repro_id33_34_40_u0000_security/run_u0000_security_repro.sh`
- `wolfMQTT/001-050/repro_id33_34_40_u0000_security_bundle.zip`

The package contains:

- one Python script that sends raw MQTT packets and verifies the three security behaviors
- one shell wrapper that starts the broker, runs the Python script, and prints the broker log tail

## Configuration

The shell wrapper accepts the following environment variables:

- `BROKER`: path to the wolfMQTT broker binary
- `TESTPY`: path to the Python reproduction script
- `PORT`: broker port, default `28986`
- `AUTH_USER`: username used to start broker auth, default `user`
- `AUTH_PASS`: password used to start broker auth, default `pass`
- `LOG`: broker log path, default `/tmp/wolfmqtt_u0000_security.log`
- `PYTHON_BIN`: Python interpreter, default `python3`

The Python script also accepts CLI options:

- `--host`
- `--port`
- `--auth-user`
- `--auth-pass`
- `--timeout`
- `--case all|auth|clientid|topic`

## How To Run

### Option 1: run the packaged shell wrapper on Linux or WSL

If you use the broker binary from this repository's current build output, run it from Linux or WSL. The tested broker binary under `build/wolfmqtt-id17-id20-test/bin/mqtt_broker` is an ELF executable.

```sh
cd /path/to/conditionFuzzing
sh wolfMQTT/001-050/repro_id33_34_40_u0000_security/run_u0000_security_repro.sh
```

Example with explicit broker path:

```sh
BROKER=/path/to/build/wolfmqtt-id17-id20-test/bin/mqtt_broker \
PORT=28986 \
AUTH_USER=user \
AUTH_PASS=pass \
sh wolfMQTT/001-050/repro_id33_34_40_u0000_security/run_u0000_security_repro.sh
```

### Option 2: run the Python script against an already running broker

Start the broker with auth enabled:

```sh
/path/to/mqtt_broker -p 28986 -v 3 -u user -P pass
```

Then run:

```sh
python3 wolfMQTT/001-050/repro_id33_34_40_u0000_security/u0000_security_repro.py \
  --host 127.0.0.1 \
  --port 28986 \
  --auth-user user \
  --auth-pass pass
```

### Expected result

If the issue is reproducible, the script exits with status `0` and reports:

- auth bypass confirmed
- ClientId collision confirmed
- topic confusion confirmed

If the broker is fixed, one or more cases should fail and the script exits non-zero.

## Why This Should Be Reported As Security-Relevant

This issue is stronger than a normal standards-compliance bug because:

- it causes authorization decisions to use the wrong identity
- it causes session management to use the wrong ClientId
- it causes routing to use the wrong topic name

That is enough to justify a security report for the stock broker.

## Recommended Fix Direction

The safest fix is to reject forbidden MQTT UTF-8 strings before broker logic stores or compares them.

Recommended handling:

1. validate every MQTT UTF-8 string for `U+0000` during decode
2. close the network connection as required by `[MQTT-1.5.3-2]`
3. avoid using plain C-string semantics for values that originate as MQTT length-prefixed strings
4. keep length-aware validation for ClientId, username, password, topic names, and topic filters

## Conclusion

The issue is real and security-relevant.

`U+0000` acceptance in wolfMQTT is not only a UTF-8 validation gap. In the built-in broker it leads to concrete auth bypass, ClientId collision, and topic routing confusion because later code interprets the same value through C-string semantics.
