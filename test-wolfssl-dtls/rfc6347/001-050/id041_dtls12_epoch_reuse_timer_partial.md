# DTLS 1.2 epoch reuse is scoped to the connection object rather than a 2MSL association window

## Summary 误报

wolfSSL increments epochs during a connection and resets sequence numbers after cipher changes, but no 2MSL reuse guard was found for new associations on the same transport tuple.

## Standard Requirement

Official standard: https://www.rfc-editor.org/rfc/rfc6347

RFC 6347 Section 4.1, Record Layer

```text
The DTLSPlaintext structure contains type, version, epoch, sequence_number, length, and fragment. The epoch is initially zero and is incremented each time a ChangeCipherSpec message is sent. The epoch and sequence number are concatenated to form the nonce/MAC sequence value. Implementations MUST NOT allow the same epoch value to be reused within two times the TCP maximum segment lifetime.
```

以上英文原文要求实现不仅要有字段编码，还要满足对应的运行时语义。

## Relevant Source Code

```c
src/internal.c:24836
ssl->keys.dtls_epoch++;
ssl->keys.dtls_prev_sequence_number_hi = ssl->keys.dtls_sequence_number_hi;
ssl->keys.dtls_prev_sequence_number_lo = ssl->keys.dtls_sequence_number_lo;
ssl->keys.dtls_sequence_number_hi = 0;
ssl->keys.dtls_sequence_number_lo = 0;
```

## Implementation Behavior

The active WOLFSSL object advances dtls_epoch and keeps current/previous sequence state. The searched code does not maintain an association-level timer preventing a newly created association from reusing epoch values within two times the TCP maximum segment lifetime.

## Inconsistency Reason

RFC 6347 prohibits reusing an epoch value within 2MSL. wolfSSL satisfies the rule inside one connection object, but the broader association-timing guarantee is not implemented in the library layer.

## Runtime Evidence

The verification script searches the DTLS implementation for MSL/maximum segment lifetime handling and confirms only per-object epoch increment logic.

## Impact

A deployment that rapidly tears down and recreates DTLS associations on the same tuple relies on the application to avoid the RFC's reuse window concern.

## Fix Direction

Document this as an application responsibility or add association-level epoch reuse tracking tied to peer tuple and a bounded 2MSL expiry.
