# ID48 Analysis: ClientId Character-Set Whitelist Is Not Explicitly Checked

## Scope

This document describes the following finding:

| ID | source_idx | Status | Risk | Category | Summary |
|---:|---:|---|---|---|---|
| 48 | 47 | Partially satisfied | medium | ClientId character-set whitelist not explicitly checked | There is no explicit implementation-level check for the MQTT 3.1.1 `1..23` byte ClientId whitelist rule. |

Checked materials:

- Standard: `D:\project\conditionFuzzing\document\mqtt-v3.1.1-os.doc`
- Codebase: `D:\project\conditionFuzzing\wolfMQTT-master`
- Repro scripts:
  - `D:\project\conditionFuzzing\wolfMQTT\001-050\repro_id48_clientid_charset_test.py`
  - `D:\project\conditionFuzzing\wolfMQTT\001-050\run_id48_clientid_charset_test.sh`

## English Standard Text

The relevant MQTT 3.1.1 rules are in Section `3.1.3 CONNECT Payload`, `Client Identifier`.

Original English text with context:

```text
The Client Identifier (ClientId) identifies the Client to the Server.
Each Client connecting to the Server has a unique ClientId.
The ClientId MUST be used by Clients and by Servers to identify state that
they hold relating to this MQTT Session between the Client and the Server
[MQTT-3.1.3-2].
```

The required whitelist acceptance rule is:

```text
The ClientId MUST be a UTF-8 encoded string as defined in Section 1.5.3
[MQTT-3.1.3-4].

The Server MUST allow ClientIds which are between 1 and 23 UTF-8 encoded bytes
in length, and that contain only the characters
"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
[MQTT-3.1.3-5].
```

The optional extension rule is:

```text
The Server MAY allow ClientId's that contain more than 23 encoded bytes.
The Server MAY allow ClientId's that contain characters not included in the
list given above.
```

If a Server rejects a ClientId, the relevant CONNACK return code is `0x02`:

```text
0x02 Connection Refused, identifier rejected

The Client identifier is correct UTF-8 but not allowed by the Server.
```

## Meaning of the Standard

This rule is easy to misread, so the two sides should be separated:

- `MUST allow`: the Server must accept ClientIds that are `1..23` UTF-8 encoded bytes and contain only `0-9`, `a-z`, `A-Z`.
- `MAY allow`: the Server may also accept ClientIds longer than 23 bytes, or ClientIds containing characters outside that list.

Therefore, accepting `abc_def`, `abc-def`, or a 24-byte ClientId is not automatically a violation. The standard allows a Server to be more permissive. The compliance baseline is that the whitelist case must be accepted.

## Code Description

### 1. ClientId is decoded as a generic MQTT UTF-8 string

File: `wolfMQTT-master/src/mqtt_packet.c:1038`

```c
tmp = MqttDecode_String(rx_payload, &mc_connect->client_id, NULL,
        (word32)(rx_buf_len - (rx_payload - rx_buf)));
if (tmp < 0) {
    return tmp;
}
```

The shared string decoder only parses the two-byte length and checks buffer bounds.

File: `wolfMQTT-master/src/mqtt_packet.c:338`

```c
int MqttDecode_String(byte *buf, const char **pstr, word16 *pstr_len, word32 buf_len)
{
    int len;
    word16 str_len;
    len = MqttDecode_Num(buf, &str_len, buf_len);
    if (len < 0) {
        return len;
    }
    if ((word32)str_len > buf_len - (word32)len) {
        return MQTT_TRACE_ERROR(MQTT_CODE_ERROR_OUT_OF_BUFFER);
    }
    buf += len;
    if (pstr_len) {
        *pstr_len = str_len;
    }
    if (pstr) {
        *pstr = (char*)buf;
    }
    return len + str_len;
}
```

There is no ClientId-specific check here for:

- byte length range `1..23`;
- membership in `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`;
- explicit policy decision to reject or allow characters outside the whitelist.

### 2. Broker stores ClientId by decoded length

File: `wolfMQTT-master/src/mqtt_broker.c:2708`

```c
if (mc.client_id) {
    word16 id_len = 0;
    if (MqttDecode_Num((byte*)mc.client_id - MQTT_DATA_LEN_SIZE,
            &id_len, MQTT_DATA_LEN_SIZE) == MQTT_DATA_LEN_SIZE) {
        ...
        BROKER_STORE_STR(bc->client_id, mc.client_id, id_len,
            BROKER_MAX_CLIENT_ID_LEN);
    }
}
```

The broker reads the MQTT string length and stores the ClientId bytes. It does not explicitly validate the MQTT 3.1.1 whitelist rule.

### 3. Only an implementation-size upper bound can reject

File: `wolfMQTT-master/src/mqtt_broker.c:2713`

```c
if (id_len >= BROKER_MAX_CLIENT_ID_LEN) {
    WBLOG_ERR(broker,
        "broker: client_id too long (%u >= %d) sock=%d",
        (unsigned)id_len, BROKER_MAX_CLIENT_ID_LEN,
        (int)bc->sock);
    ...
    ack.return_code =
        MQTT_CONNECT_ACK_CODE_REFUSED_ID;
    goto send_connack;
}
```

This is an implementation storage limit, not the MQTT 3.1.1 `1..23 + whitelist` rule. In the checked header, the default broker storage limit is larger than 23:

File: `wolfMQTT-master/wolfmqtt/mqtt_broker.h:89`

```c
#ifndef BROKER_MAX_CLIENT_ID_LEN
    #define BROKER_MAX_CLIENT_ID_LEN 64
#endif
```

So a 24-byte ClientId can be accepted when it fits the broker storage limit. That is allowed by MQTT 3.1.1 because `>23` is a `MAY allow` case.

### 4. Default CONNACK path accepts unless a later branch rejects

File: `wolfMQTT-master/src/mqtt_broker.c:2917`

```c
ack.flags = 0;
ack.return_code = MQTT_CONNECT_ACK_CODE_ACCEPTED;
```

File: `wolfMQTT-master/src/mqtt_broker.c:3023`

```c
rc = MqttEncode_ConnectAck(bc->tx_buf, BROKER_CLIENT_TX_SZ(bc), &ack);
```

Since there is no whitelist rejection branch, ClientIds with `_`, `-`, `/`, spaces, `$`, and non-ASCII UTF-8 are accepted as long as other checks pass.

## Dynamic Test Evidence

The repro script sends MQTT 3.1.1 CONNECT packets with `CleanSession=1`. This avoids mixing the test with zero-length ClientId session rules.

Tested whitelist-valid ClientIds:

```text
A
AbCdEfGhIjKlMnOpQrStUvW    (23 bytes)
0123456789
```

Observed result:

```text
All returned CONNACK 20020000, return_code=0, PINGRESP d000.
```

Tested non-whitelist or extension ClientIds:

```text
abc_def          contains underscore
abc-def          contains hyphen
abc/def          contains slash
abc def          contains space
abc$def          contains dollar sign
non-ASCII UTF-8  contains bytes outside ASCII alnum
AbCdEfGhIjKlMnOpQrStUvWx    24 bytes
```

Observed result:

```text
All returned CONNACK 20020000, return_code=0, PINGRESP d000.
```

Representative output:

```text
allowed_len23 -> connack_hex=20020000, return_or_reason_code=0, alive_after_connack=true
non_whitelist_underscore -> connack_hex=20020000, return_or_reason_code=0, alive_after_connack=true
non_whitelist_hyphen -> connack_hex=20020000, return_or_reason_code=0, alive_after_connack=true
non_whitelist_space -> connack_hex=20020000, return_or_reason_code=0, alive_after_connack=true
len24_whitelist_chars -> connack_hex=20020000, return_or_reason_code=0, alive_after_connack=true
```

## Inconsistency Reason

The implementation does not encode the MQTT 3.1.1 ClientId whitelist rule as an explicit validation branch. Instead, it behaves as a permissive implementation:

- whitelist-valid `1..23` byte ClientIds are accepted;
- non-whitelist ClientIds are also accepted;
- ClientIds longer than 23 bytes are accepted if they fit the broker storage limit;
- rejection is tied to implementation storage capacity, not to the normative `1..23 + whitelist` text.

This means the implementation satisfies the observable `MUST allow` part for the tested whitelist cases. However, it does not make the standard rule explicit in code, and it does not document a clear policy boundary between the required whitelist and optional extension cases.

## Conclusion

The dynamic test does not show a hard MQTT 3.1.1 violation for ID48, because MQTT 3.1.1 permits a Server to allow ClientIds outside the `1..23` whitelist set.

The finding is still useful as a documentation and traceability issue:

```text
wolfMQTT accepts the required whitelist ClientIds, but does not explicitly
implement or document the MQTT-3.1.3-5 whitelist acceptance rule as a
ClientId-specific check. It also accepts optional extension cases under the
same generic storage path.
```

Recommended classification:

```text
ID48: partially satisfied / medium-to-low
Reason: whitelist-valid ClientIds are accepted, but the normative length and
character-set rule is not explicitly represented in the implementation.
```
