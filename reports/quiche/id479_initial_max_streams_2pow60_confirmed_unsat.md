# initial_max_streams above 2^60 Is Clamped Instead of Rejected

## Summary

RFC 9000 requires an endpoint to close the connection with `TRANSPORT_PARAMETER_ERROR` when it receives a `max_streams` transport parameter with a value greater than `2^60`. This applies to `initial_max_streams_bidi` and `initial_max_streams_uni`.

quiche parses these transport parameters as generic varint62 integer parameters, accepts values up to `kVarInt62MaxValue`, and later clamps the received values to `uint32_t::max()` when storing them in `QuicConfig`. The implementation avoids internal overflow, but it does not reject the protocol-invalid value as required by RFC 9000.

## Standard Requirement

- RFC 9000 Section 4.6, Controlling Concurrency
- RFC 9000 Section 18.2, Transport Parameter Definitions
- RFC 9000 Section 19.11, MAX_STREAMS Frames
- Link: https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6
- Link: https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2
- Link: https://www.rfc-editor.org/rfc/rfc9000.html#section-19.11

```text
If a max_streams transport parameter or a MAX_STREAMS frame is received with a
value greater than 2^60, this would allow a maximum stream ID that cannot be
expressed as a variable-length integer; see Section 16. If either is received,
the connection MUST be closed immediately with a connection error of type
TRANSPORT_PARAMETER_ERROR if the offending value was received in a transport
parameter or of type FRAME_ENCODING_ERROR if it was received in a frame; see
Section 10.2.
```

```text
initial_max_streams_bidi (0x08):

The initial maximum bidirectional streams parameter is an integer value that
contains the initial maximum number of bidirectional streams the endpoint that
receives this transport parameter is permitted to initiate.

initial_max_streams_uni (0x09):

The initial maximum unidirectional streams parameter is an integer value that
contains the initial maximum number of unidirectional streams the endpoint that
receives this transport parameter is permitted to initiate.
```

The initial max streams transport parameters are `max_streams` transport parameters. Values greater than `2^60` must be rejected with `TRANSPORT_PARAMETER_ERROR`.

## Relevant Source Code

Source: `quiche-main/quiche-main/quiche/quic/core/crypto/transport_parameters.cc:263-310`

```cpp
263: TransportParameters::IntegerParameter::IntegerParameter(
264:     TransportParameters::TransportParameterId param_id, uint64_t default_value,
265:     uint64_t min_value, uint64_t max_value)
266:     : param_id_(param_id),
267:       value_(default_value),
268:       default_value_(default_value),
269:       min_value_(min_value),
270:       max_value_(max_value),
271:       has_been_read_(false) {
272:   QUICHE_DCHECK_LE(min_value, default_value);
273:   QUICHE_DCHECK_LE(default_value, max_value);
274:   QUICHE_DCHECK_LE(max_value, quiche::kVarInt62MaxValue);
275: }
277: TransportParameters::IntegerParameter::IntegerParameter(
278:     TransportParameters::TransportParameterId param_id)
279:     : TransportParameters::IntegerParameter::IntegerParameter(
280:           param_id, 0, 0, quiche::kVarInt62MaxValue) {}
302: bool TransportParameters::IntegerParameter::Read(QuicDataReader* reader,
303:                                                  std::string* error_details) {
304:   if (has_been_read_) {
305:     *error_details =
306:         "Received a second " + TransportParameterIdToString(param_id_);
307:     return false;
308:   }
309:   has_been_read_ = true;
310:   return ReadIntegerValue(reader, param_id_, value_, error_details);
```

The default integer-parameter constructor allows values up to `kVarInt62MaxValue`.

Source: `quiche-main/quiche-main/quiche/quic/core/crypto/transport_parameters.cc:506-516`

```cpp
506: TransportParameters::TransportParameters()
507:     : max_idle_timeout_ms(kMaxIdleTimeout),
508:       max_udp_payload_size(kMaxPacketSize, kDefaultMaxPacketSizeTransportParam,
509:                            kMinMaxPacketSizeTransportParam,
510:                            quiche::kVarInt62MaxValue),
511:       initial_max_data(kInitialMaxData),
512:       initial_max_stream_data_bidi_local(kInitialMaxStreamDataBidiLocal),
513:       initial_max_stream_data_bidi_remote(kInitialMaxStreamDataBidiRemote),
514:       initial_max_stream_data_uni(kInitialMaxStreamDataUni),
515:       initial_max_streams_bidi(kInitialMaxStreamsBidi),
516:       initial_max_streams_uni(kInitialMaxStreamsUni),
```

`initial_max_streams_bidi` and `initial_max_streams_uni` use the default integer-parameter bounds.

Source: `quiche-main/quiche-main/quiche/quic/core/crypto/transport_parameters.cc:1388-1394`

```cpp
1388:       case TransportParameters::kInitialMaxStreamsBidi:
1389:         parse_success =
1390:             out->initial_max_streams_bidi.Read(&value_reader, error_details);
1391:         break;
1392:       case TransportParameters::kInitialMaxStreamsUni:
1393:         parse_success =
1394:             out->initial_max_streams_uni.Read(&value_reader, error_details);
```

The parser reads both values through the generic integer parameter reader.

Source: `quiche-main/quiche-main/quiche/quic/core/quic_config.cc:1363-1370`

```cpp
1363:   // IETF QUIC specifies stream IDs and stream counts as 62-bit integers but
1364:   // our implementation uses uint32_t to represent them to save memory.
1365:   max_bidirectional_streams_.SetReceivedValue(
1366:       std::min<uint64_t>(params.initial_max_streams_bidi.value(),
1367:                          std::numeric_limits<uint32_t>::max()));
1368:   max_unidirectional_streams_.SetReceivedValue(
1369:       std::min<uint64_t>(params.initial_max_streams_uni.value(),
1370:                          std::numeric_limits<uint32_t>::max()));
```

During configuration processing, quiche clamps the received values to `uint32_t::max()`.

## Implementation Behavior

When receiving `initial_max_streams_bidi` or `initial_max_streams_uni`, quiche accepts any syntactically valid varint62 value allowed by the generic integer parameter reader. The reviewed code does not reject values greater than `2^60` during parsing.

After parsing, `QuicConfig::ProcessTransportParameters` stores the values after clamping them to `uint32_t::max()`. This prevents the implementation from storing very large stream-count values internally, but it also means the peer's invalid transport parameter is accepted rather than causing the required connection close.

## Inconsistency Reason

The standard requires immediate connection close with `TRANSPORT_PARAMETER_ERROR` when a `max_streams` transport parameter is greater than `2^60`.

quiche does not enforce that protocol limit for `initial_max_streams_bidi` or `initial_max_streams_uni`. It parses the value and later clamps it to an implementation limit. Clamping is not equivalent to rejecting the invalid transport parameter.

## Impact

A peer can advertise `initial_max_streams_bidi` or `initial_max_streams_uni` above `2^60` without triggering the RFC-required transport-parameter error. quiche will continue with a reduced local value, which can hide peer misbehavior and cause conformance tests to observe acceptance where a connection close is required.

## Fix Direction

Add an explicit protocol-limit check for `initial_max_streams_bidi` and `initial_max_streams_uni`.

If either received value is greater than `2^60`, close the connection with `TRANSPORT_PARAMETER_ERROR` instead of clamping and continuing.
