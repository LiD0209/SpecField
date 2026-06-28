# Reserved Bits Receive Validation

## Summary

RFC 9000 requires QUIC endpoints to close the connection with `PROTOCOL_VIOLATION` when a received packet has non-zero reserved header bits after packet protection and header protection are removed.

quiche correctly clears reserved bits when it writes IETF QUIC packet headers. The receive path, however, removes header protection and reconstructs the packet number length without checking the reserved-bit fields. If the packet decrypts successfully, processing continues into `OnPacketHeader()` and frame parsing.

This is not a clean false positive:

- public-header parsing happens before header protection is removed, so it cannot validate the protected reserved bits;
- AEAD authentication only detects unauthorized modification, not a peer that intentionally sends an authenticated packet with non-zero reserved bits;
- the located post-decryption path does not close with `IETF_QUIC_PROTOCOL_VIOLATION` based on the long-header `0x0c` mask or the short-header `0x18` mask.

## Standard Requirement

Standard: [RFC 9000 Section 17.2](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2) and [RFC 9000 Section 17.3.1](https://www.rfc-editor.org/rfc/rfc9000.html#section-17.3.1)

For long headers, RFC 9000 Section 17.2 defines two protected reserved bits:

```text
Reserved Bits:

Two bits (those with a mask of 0x0c) of byte 0 are reserved across multiple packet types. These bits are protected using header protection; see Section 5.4 of [QUIC-TLS]. The value included prior to protection MUST be set to 0. An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.
```

For short headers, RFC 9000 Section 17.3.1 defines two protected reserved bits:

```text
Reserved Bits:

The next two bits (those with a mask of 0x18) of byte 0 are reserved. These bits are protected using header protection; see Section 5.4 of [QUIC-TLS]. The value included prior to protection MUST be set to 0. An endpoint MUST treat receipt of a packet that has a non-zero value for these bits, after removing both packet and header protection, as a connection error of type PROTOCOL_VIOLATION.
```

The receive-side rule is therefore precise:

- after header protection is removed, long-header packets must reject `(type_byte & 0x0c) != 0`;
- after header protection is removed, short-header packets must reject `(type_byte & 0x18) != 0`;
- the error must be a QUIC transport `PROTOCOL_VIOLATION`.

## Relevant Source Code

quiche's writer leaves reserved bits clear before header protection is applied.

Source: `quiche-main/quiche-main/quiche/quic/core/quic_framer.cc:2049-2058`

```cpp
if (header.version_flag) {
  type = static_cast<uint8_t>(
      FLAGS_LONG_HEADER | FLAGS_FIXED_BIT |
      LongHeaderTypeToOnWireValue(header.long_packet_type, version_) |
      PacketNumberLengthToOnWireValue(header.packet_number_length));
} else {
  type = static_cast<uint8_t>(
      FLAGS_FIXED_BIT | (current_key_phase_bit_ ? FLAGS_KEY_PHASE_BIT : 0) |
      (header.spin_bit ? FLAGS_SPIN_BIT : 0) |
      PacketNumberLengthToOnWireValue(header.packet_number_length));
}
```

For long headers, this sets only the long-header bit, fixed bit, packet type, and packet number length. It does not set the `0x0c` reserved bits. For short headers, it sets the fixed bit, optional key phase, optional spin bit, and packet number length. It does not set the `0x18` reserved bits.

The receive path removes header protection from the protected bits of byte 0. It uses `0x0f` for long headers and `0x1f` for short headers, which covers the RFC reserved bits in both formats:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_framer.cc:4421-4435`

```cpp
// Unmask the rest of the type byte.
uint8_t bitmask = 0x1f;
if (IsLongHeader(header->type_byte)) {
  bitmask = 0x0f;
}
uint8_t mask_byte;
if (!mask_reader.ReadUInt8(&mask_byte)) {
  QUIC_DVLOG(1) << "No first byte to read from mask";
  return false;
}
header->type_byte ^= (mask_byte & bitmask);

// Compute the packet number length.
header->packet_number_length =
    static_cast<QuicPacketNumberLength>((header->type_byte & 0x03) + 1);
```

After unmasking, the code immediately derives packet number length from the low two bits. There is no reserved-bit check before continuing.

The same unmasked type byte is written into associated data for AEAD verification:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_framer.cc:4459-4470`

```cpp
absl::string_view ad = GetAssociatedDataFromEncryptedPacket(
    version.transport_version, packet,
    GetIncludedDestinationConnectionIdLength(*header),
    GetIncludedSourceConnectionIdLength(*header), header->version_flag,
    has_diversification_nonce, header->packet_number_length,
    header->retry_token_length_length, header->retry_token.length(),
    header->length_length);
associated_data.assign(ad.begin(), ad.end());
QuicDataWriter ad_writer(associated_data.size(), associated_data.data());

// Apply the unmasked type byte and packet number to |associated_data|.
if (!ad_writer.WriteUInt8(header->type_byte)) {
```

This verifies that byte 0 is authenticated, but it does not enforce the RFC rule that authenticated non-zero reserved bits are a protocol violation.

After successful decryption, packet processing continues to the visitor and then to frame parsing:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_framer.cc:1926-1936`

```cpp
if (!visitor_->OnPacketHeader(*header)) {
  RecordDroppedPacketReason(DroppedPacketReason::INVALID_PACKET_NUMBER);
  // The visitor suppresses further processing of the packet.
  return true;
}

// Handle the payload.
if (VersionIsIetfQuic(version_.transport_version)) {
  current_received_frame_type_ = 0;
  previously_received_frame_type_ = 0;
```

`QuicConnection::OnPacketHeader()` uses the header for spin-bit handling, migration state, packet accounting, and validation of other packet properties. It does not check the reserved-bit masks:

Source: `quiche-main/quiche-main/quiche/quic/core/quic_connection.cc:1263-1305`

```cpp
bool QuicConnection::OnPacketHeader(const QuicPacketHeader& header) {
  if (spin_bit_enabled_ && header.form == IETF_QUIC_SHORT_HEADER_PACKET) {
    QUIC_CODE_COUNT(quic_enable_spin_bit);
    QuicPacketNumber largest_observed =
        uber_received_packet_manager_.GetLargestObserved(
            ENCRYPTION_FORWARD_SECURE);
    if (!largest_observed.IsInitialized() ||
        header.packet_number > largest_observed) {
      PathState* absl_nonnull path = &default_path_;
      ...
    }
  }

  if (debug_visitor_ != nullptr) {
    debug_visitor_->OnPacketHeader(header, clock_->ApproximateNow(),
                                   last_received_packet_info_.decrypted_level);
  }

  // Will be decremented below if we fall through to return true.
  ++stats_.packets_dropped;

  if (!ProcessValidatedPacket(header)) {
    return false;
  }
```

## Implementation Behavior

quiche implements the transmit-side half of the requirement: it constructs outgoing IETF packet type bytes with reserved bits clear before applying header protection.

The receive-side behavior is incomplete. Once `RemoveHeaderProtection()` has recovered `header->type_byte`, quiche has exactly the value needed to enforce RFC 9000:

```text
long header:  reject if (header->type_byte & 0x0c) != 0
short header: reject if (header->type_byte & 0x18) != 0
```

The located code does not perform either check. Instead, it computes packet number length, reconstructs the associated data, decrypts the packet, and then processes the header and payload if decryption succeeds.

## Inconsistency Reason

The standard requires two distinct behaviors:

1. senders set reserved bits to zero before protection;
2. receivers treat authenticated packets with non-zero reserved bits as `PROTOCOL_VIOLATION` after protection is removed.

quiche satisfies the first behavior but not the second.

The missing receive-side check is not covered by public-header parsing. `ParsePublicHeader()` runs before header protection removal, when these bits are still protected and do not yet have their RFC-defined values.

The missing receive-side check is also not covered by AEAD authentication. AEAD prevents an on-path attacker from modifying protected bits without detection. It does not reject a packet that was intentionally generated by the peer with non-zero reserved bits and a valid authentication tag. RFC 9000 still requires that packet to close the connection with `PROTOCOL_VIOLATION`.

## Impact

The practical impact is protocol-compliance and robustness risk rather than a direct encryption bypass.

- An unauthorized middlebox that flips reserved bits will generally cause decryption failure, not a clean protocol-violation close.
- A malicious or non-compliant peer that can generate authenticated packets can send non-zero reserved bits and have them reach deeper packet and frame processing instead of being rejected at the header-validation point.
- Initial packets have publicly derivable initial keys, so malformed-but-authenticated Initial packets are easier to construct than later encrypted packets.
- The behavior can be used for implementation fingerprinting because a compliant peer should close with `PROTOCOL_VIOLATION`, while this path may continue or fail for a different reason.

This should be treated as a real RFC 9000 receive-validation gap. The risk is medium-low to medium unless a follow-up reproducer shows that these packets trigger additional state-machine, resource-consumption, or crash behavior.

## Fix Direction

Add an explicit reserved-bit validation immediately after `RemoveHeaderProtection()` recovers `header->type_byte` and before packet number processing proceeds further.

A direct fix would check the packet format and reject authenticated packets with non-zero reserved bits using `IETF_QUIC_PROTOCOL_VIOLATION`, for example:

```text
if long header and (type_byte & 0x0c) != 0 -> PROTOCOL_VIOLATION
if short header and (type_byte & 0x18) != 0 -> PROTOCOL_VIOLATION
```

Focused tests should cover both packet formats:

- an Initial or Handshake packet whose unprotected long-header reserved bits are non-zero;
- a 1-RTT short-header packet whose unprotected short-header reserved bits are non-zero;
- both cases should produce an IETF transport close mapped to `PROTOCOL_VIOLATION`, not normal frame processing and not a generic packet-header error.
