# OfferedPsks.identities lower-bound inconsistency (OpenSSL vs RFC 8446)

## 1. Conclusion

This issue concerns the minimum length constraint on `OfferedPsks.identities`.
RFC 8446 requires `identities<7..2^16-1>`, but the current OpenSSL code path does not enforce a unified hard-fail check for this lower bound. Therefore this item is classified as **Partially Satisfied**.

## 2. RFC 8446 English Source Text

### 2.1 `pre_shared_key` extension structure definition

From [RFC 8446 (TLS 1.3), Section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11):

```text
The "extension_data" field of this extension contains a
"PreSharedKeyExtension" value:

   struct {
       opaque identity<1..2^16-1>;
       uint32 obfuscated_ticket_age;
   } PskIdentity;

   opaque PskBinderEntry<32..255>;

   struct {
       PskIdentity identities<7..2^16-1>;
       PskBinderEntry binders<33..2^16-1>;
   } OfferedPsks;

   struct {
       select (Handshake.msg_type) {
           case client_hello: OfferedPsks;
           case server_hello: uint16 selected_identity;
       };
   } PreSharedKeyExtension;
```

The key constraint is:

```text
PskIdentity identities<7..2^16-1>;
```

### 2.2 Vector syntax lower-bound meaning

From [RFC 8446, Section 3.4](https://www.rfc-editor.org/rfc/rfc8446#section-3.4):

```text
Variable-length vectors are defined by specifying a subrange of legal
lengths, inclusively, using the notation <floor..ceiling>.
```

The `7` in `<7..2^16-1>` is the inclusive lower bound on the encoded byte length.

### 2.3 Parse-failure handling semantics

From [RFC 8446, Section 6](https://www.rfc-editor.org/rfc/rfc8446#section-6):

```text
Peers which receive a message which cannot be parsed according to the
syntax (e.g., have a length extending beyond the message boundary or
contain an out-of-range length) MUST terminate the connection with a
"decode_error" alert.
```

## 3. OpenSSL Code Description

### 3.1 Reading the identities vector

OpenSSL reads the `identities` vector in `tls_parse_ctos_psk()` in `ssl/statem/extensions_srvr.c`:

```c
if (!PACKET_get_length_prefixed_2(pkt, &identities)) {
    SSLfatal(...);
    return 0;
}
```

### 3.2 Behavior boundary of `PACKET_get_length_prefixed_2`

This API only guarantees that the length prefix can be read and that the byte range does not overflow. It does not enforce the RFC floor value.

### 3.3 Empty identities do not trigger an error in this segment

The subsequent loop condition is:

```c
for (id = 0; PACKET_remaining(&identities) != 0; id++) {
    ...
}
```

When `identities` has length `0` (clearly below the RFC lower bound of 7), the loop body is never entered and no error is raised in this segment.

## 4. Root Cause of Inconsistency

The inconsistency comes from a mismatch between the constraint level in the spec and the check level in the implementation:

1. RFC treats `<floor..ceiling>` as a syntactic validity constraint that includes the lower bound.
2. The OpenSSL path focuses on prefix parsing and memory safety, without a unified `>= 7` hard check on the `identities` vector length.
3. As a result, inputs that are parseable but violate the RFC minimum length can pass through this parsing segment.

## 5. Test Evidence

Runtime output from `runtime_retest/id307/test_psk_identities_lower_bound.out`:

```text
[empty_identities_len0] parse_ok=1 entries=0 zero_len_identity_seen=0
```

When `identities` length is `0`, this parsing path still returns success, which supports the inconsistency conclusion.
