# Summary
OpenSSL does not strictly enforce RFC 8446 when a TLS 1.3 HelloRetryRequest carries an empty Cookie. Under the RFC, cookie<1..2^16-1> forbids zero-length values, and receiving such an out-of-range field should cause the peer to abort the connection immediately with a decode_error. However, the observed OpenSSL client accepts the malformed HRR, continues with a second ClientHello, and only fails later with bad_record_mac, indicating that the invalid empty Cookie is not rejected at parse time as required.

# Cookie Length Requirement vs OpenSSL Runtime Behavior

## Standard Description (RFC 8446)

### 1) Vector syntax and non-empty lower bound
```text
Variable-length vectors are defined by specifying a subrange of legal
lengths, inclusively, using the notation <floor..ceiling>.
...
In the following example, "mandatory" is a vector that must contain
between 300 and 400 bytes of type opaque.  It can never be empty.
```

### 2) Cookie grammar
```text
struct {
    opaque cookie<1..2^16-1>;
} Cookie;
```

### 3) Error-handling requirement
```text
Peers which receive a message which cannot be parsed according to the syntax
(e.g., ... an out-of-range length) MUST terminate the connection with a
"decode_error" alert.

Peers which receive a message which is syntactically correct but semantically
invalid ... MUST terminate the connection with an "illegal_parameter" alert.
```

### 4) Meaning of terminate/abort
```text
... without sending or receiving any additional data.
```

## OpenSSL Code Description

### Client parsing of cookie from HRR
Source: `openssl-master/ssl/statem/extensions_clnt.c`

```c
if (!PACKET_as_length_prefixed_2(pkt, &cookie)
    || !PACKET_memdup(&cookie, &s->ext.tls13_cookie,
        &s->ext.tls13_cookie_len)) {
    SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_LENGTH_MISMATCH);
    return 0;
}
```

Observation: this path checks prefix/decode success and memory copy, but does not show an explicit `cookie_len > 0` rejection branch.

### Client construction of cookie in the second ClientHello
Source: `openssl-master/ssl/statem/extensions_clnt.c`

```c
/* Should only be set if we've had an HRR */
if (s->ext.tls13_cookie_len == 0)
    return EXT_RETURN_NOT_SENT;
```

Observation: if stored cookie length is `0`, the client-side construction path simply does not send the cookie extension.

## Runtime Observation

After modifying the HRR cookie to empty (`length = 0`), we observed:

1. Empty cookie bytes were injected into HRR:
```text
... 00 2c 00 02 00 00
```

2. The client still sent the second `ClientHello` (instead of immediate abort with `decode_error` / `illegal_parameter`).

3. Final failure was:
```text
fatal bad_record_mac
decryption failed or bad record mac
```

## Conclusion
The code does not strictly comply with the standards, and when the cookie is empty, it directly rejects the handshake
