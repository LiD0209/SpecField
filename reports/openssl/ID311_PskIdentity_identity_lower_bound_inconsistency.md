# PskIdentity.identity lower-bound inconsistency (OpenSSL vs RFC 8446)

## 1. Conclusion

This issue concerns the minimum length constraint on `PskIdentity.identity`.
RFC 8446 explicitly requires `identity<1..2^16-1>`, but the current OpenSSL server parsing path does not uniformly reject `identity_len = 0`. Therefore this item is classified as **Partially Satisfied**.

## 2. RFC 8446 English Source Text

### 2.1 `pre_shared_key` structure and `identity` constraint

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
```

The key line is:

```text
opaque identity<1..2^16-1>;
```

### 2.2 `identity` field semantic description

From [RFC 8446, Section 4.2.11](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.11):

```text
identity:  A label for a key.  For instance, a ticket (as defined in
   Appendix B.3.4) or a label for a pre-shared key established
   externally.
```

### 2.3 Vector syntax lower bound and parse-failure semantics

From [RFC 8446, Section 3.4](https://www.rfc-editor.org/rfc/rfc8446#section-3.4):

```text
Variable-length vectors are defined by specifying a subrange of legal
lengths, inclusively, using the notation <floor..ceiling>.
```

From [RFC 8446, Section 6](https://www.rfc-editor.org/rfc/rfc8446#section-6):

```text
Peers which receive a message which cannot be parsed according to the
syntax ... or contain an out-of-range length) MUST terminate the
connection with a "decode_error" alert.
```

## 3. OpenSSL Code Description

### 3.1 How `identity` is parsed

In `tls_parse_ctos_psk()` in `ssl/statem/extensions_srvr.c`, each identity is processed as:

```c
if (!PACKET_get_length_prefixed_2(&identities, &identity)
    || !PACKET_get_net_4(&identities, &ticket_agel)) {
    SSLfatal(...);
    return 0;
}

idlen = PACKET_remaining(&identity);
```

`idlen` is read here, but there is no unified hard-fail check enforcing `idlen >= 1`.

### 3.2 Subsequent processing does not treat an empty identity as a syntax-layer error

Later code enters callback, lookup, or ticket-flow branches, for example:

```c
if (sess == NULL
    && s->psk_server_callback != NULL
    && idlen <= PSK_MAX_IDENTITY_LEN) {
    ...
}
```

This only checks an upper bound; it is not equivalent to the RFC lower-bound hard check.

## 4. Root Cause of Inconsistency

The core mismatch is:

1. RFC defines `identity<1..>` as a syntactic validity constraint (identity must be non-empty).
2. The OpenSSL path primarily checks parseability, bounds safety, and whether processing can continue semantically. It does not enforce a minimum-length hard failure at the identity read point.
3. As a result, a syntactically invalid empty identity may continue into subsequent branches instead of being rejected immediately.

## 5. Test Evidence

Runtime output from `runtime_retest/id307/test_psk_identities_lower_bound.out`:

```text
[single_zero_len_identity_len6] parse_ok=1 entries=1 zero_len_identity_seen=1
```

`identity_len = 0` still passes through this parsing segment, which supports the conclusion that no unified hard failure exists.
