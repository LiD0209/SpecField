# Heartbeat Demultiplexing Is Not Implemented

## Summary

RFC 9147 lists Heartbeat as a DTLS < 1.3 record type in the demultiplexing table. BoringSSL's shipped DTLS record layer does not provide a Heartbeat dispatch path, so Heartbeat records are not processed by product `libssl`.

This confirms ID 152 as **partially satisfied**.

## Standard Requirement

Official standard: <https://www.rfc-editor.org/rfc/rfc9147>

Relevant section: `4.1 Demultiplexing DTLS Records`

Original English requirement excerpt:

```text
OCT == 24   -+--> Heartbeat (DTLS <1.3)
```

## Code Behavior

In `ssl/d1_pkt.cc`, the DTLS record dispatch path routes ACK and application data, but has no Heartbeat branch:

```cpp
if (type == SSL3_RT_ACK) {
  return dtls1_process_ack(ssl, out_alert, record_number, record);
}

if (type != SSL3_RT_APPLICATION_DATA) {
  OPENSSL_PUT_ERROR(SSL, SSL_R_UNEXPECTED_RECORD);
```

Static review found no `SSL3_RT_HEARTBEAT` handler in the product DTLS path.

## Runner Coverage

`ssl/test/runner` contains DTLS protocol simulation and can exercise unsupported-record rejection, but it does not add a product Heartbeat parser or handler to `libssl`.

## Runtime Evidence

Focused static test:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\151-187\focused_static_id152_153_185_187.py
```

Linked probe log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\151-187\repro_dtls13_151_187_linked_probe.log
```

Observed output excerpt:

```text
ID152 heartbeat content type is not defined: PASS
ID152 non-handshake dispatch has no heartbeat branch: PASS
```

## Inconsistency

| RFC 9147 requirement component | BoringSSL behavior |
|---|---|
| Demultiplex Heartbeat records | No Heartbeat branch in product DTLS dispatch |
| Handle Heartbeat as a DTLS < 1.3 record type | Unsupported records are rejected/not dispatched |

## Root Cause

BoringSSL does not implement Heartbeat demultiplexing in the shipped DTLS record layer.

## Impact

Deployments that require DTLS Heartbeat handling cannot rely on this product path to process Heartbeat records.

## Suggested Fix

Add an explicit Heartbeat dispatch and handling path if Heartbeat support is required by the target protocol profile.
