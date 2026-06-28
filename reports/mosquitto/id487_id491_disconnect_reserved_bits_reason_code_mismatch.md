# Mosquitto Uses DISCONNECT 0x82 Instead of 0x81 For DISCONNECT Reserved-Bit Violations

## Conclusion

MQTT 5 requires invalid fixed-header flags on `DISCONNECT` to be classified as
`Malformed Packet`, which corresponds to `DISCONNECT 0x81`.

Mosquitto does check those reserved bits and does disconnect the peer, but it
returns `MOSQ_ERR_PROTOCOL` for that condition. The MQTT 5 read-dispatch layer
then maps that to `DISCONNECT 0x82 (Protocol Error)`.

This same reason-code mismatch covers both item `487` and item `491`.

## MQTT Standard Requirement

- Standard: [MQTT Version 5.0 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- Section `2.1.3` Fixed Header Flags
- Section `3.14.1` DISCONNECT Fixed Header
- Section `4.13` Handling errors

The key normative text is:

```text
The Fixed Header flags for this packet type MUST be set to the value
listed in Table 2-2.

If invalid flags are received it is a Malformed Packet.
```

For `DISCONNECT`, the low four bits are reserved and must be `0000`.

That means:

- non-zero reserved bits on `DISCONNECT` are not just a generic protocol mistake
- the specification classifies them specifically as `Malformed Packet`
- the corresponding MQTT 5 wire reason code is `0x81`, not `0x82`

## Relevant Code

### The Reserved-Bit Check Exists

`src/handle_disconnect.c` validates the low four bits:

```c
if(context->protocol == mosq_p_mqtt311 || context->protocol == mosq_p_mqtt5){
	if((context->in_packet.command&0x0F) != 0x00){
		log__printf(NULL, MOSQ_LOG_INFO, "Protocol error from %s: DISCONNECT packet with incorrect flags %02X.",
				context->id, context->in_packet.command);
		return MOSQ_ERR_PROTOCOL;
	}
}
```

So mosquitto is not missing the check itself.

### The Internal Classification Is The Problem

The same branch returns:

```text
MOSQ_ERR_PROTOCOL
```

Then `src/read_handle.c` performs the MQTT 5 reason-code mapping:

```c
if(context->protocol == mosq_p_mqtt5){
	if(rc == MOSQ_ERR_PROTOCOL || rc == MOSQ_ERR_DUPLICATE_PROPERTY){
		send__disconnect(context, MQTT_RC_PROTOCOL_ERROR, NULL);
	}else if(rc == MOSQ_ERR_MALFORMED_PACKET){
		send__disconnect(context, MQTT_RC_MALFORMED_PACKET, NULL);
	}
	...
}
```

That means the end-to-end behavior is:

```text
invalid DISCONNECT reserved bits
-> handle__disconnect() returns MOSQ_ERR_PROTOCOL
-> read_handle maps that to MQTT_RC_PROTOCOL_ERROR
-> broker sends DISCONNECT 0x82
```

But the MQTT 5 classification should be:

```text
invalid DISCONNECT reserved bits
-> malformed packet
-> DISCONNECT 0x81
```

## Runtime Evidence

This behavior was already reproduced on the same code path in the earlier audit
batch and is explicitly reused here because the implementation branch is the
same.

Observed runtime result:

```text
bad_disconnect_flags -> e0 01 82
```

Packet interpretation:

```text
e0 01 82 = DISCONNECT Protocol Error
```

Expected MQTT 5 result:

```text
e0 01 81 = DISCONNECT Malformed Packet
```

That means:

- the peer is disconnected, so the validation is active
- but the wire-visible reason code is wrong
- the mismatch is therefore in classification, not in basic enforcement

## Why This Is Partial

Implemented:

- invalid reserved bits are detected
- the connection is terminated

Missing:

- the condition is not classified as `Malformed Packet`
- the outgoing MQTT 5 reason code is therefore `0x82` instead of `0x81`

So this is a narrower classification bug, not a total lack of validation.

## Suggested Fix

For this specific branch, `handle__disconnect()` should return
`MOSQ_ERR_MALFORMED_PACKET` instead of `MOSQ_ERR_PROTOCOL`, so the existing
dispatch layer will emit:

```text
DISCONNECT 0x81
```
