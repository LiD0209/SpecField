# PMTU Retransmission Backoff Is Only Partially Implemented

## Summary

RFC 9147 says that when repeated retransmissions do not produce a response and the PMTU is unknown, later retransmissions should back off to a smaller record size and fragment handshake messages as needed.

BoringSSL partially implements this behavior. After more than two retransmission timeouts, the product code queries the write BIO for `BIO_CTRL_DGRAM_GET_FALLBACK_MTU`. If the BIO returns a valid fallback MTU, BoringSSL updates `ssl->d1->mtu`, and later retransmission uses the current MTU to fragment and seal records.

The remaining gap is the unknown-PMTU case where no valid BIO fallback MTU is available. BoringSSL does not derive progressively smaller record sizes on its own. Runner coverage exercises retransmission after manually changing MTU, but it does not cover automatic unknown-PMTU backoff after repeated no-response retransmissions.

This confirms RFC 9147 ID 093 as **partially satisfied**.

## Standard Requirement

RFC 9147, Section 4.3, "Transport Layer Mapping":

```text
DTLS messages MAY be fragmented into multiple DTLS records.  Each
DTLS record MUST fit within a single datagram.  In order to avoid IP
fragmentation, clients of the DTLS record layer SHOULD attempt to
size records so that they fit within any Path MTU (PMTU) estimates
obtained from the record layer.
```

RFC 9147, Section 4.4, "PMTU Issues":

```text
If repeated retransmissions do not result in a response, and the
PMTU is unknown, subsequent retransmissions SHOULD back off to a
smaller record size, fragmenting the handshake message as
appropriate.  This specification does not specify an exact number
of retransmits to attempt before backing off, but 2-3 seems
appropriate.
```

RFC 9147, Section 5.5, "Sending and Receiving Handshake Messages":

```text
DTLS implementations MUST be able to handle overlapping fragment
ranges.  This allows senders to retransmit handshake messages with
smaller fragment sizes if the PMTU estimate changes.  Senders MUST
NOT change handshake message bytes upon retransmission.
```

The expected lifecycle is:

| State | Expected behavior |
|---|---|
| PMTU estimate is known | Size records to fit the estimated PMTU |
| Retransmission uses a smaller PMTU | Re-fragment the same handshake bytes into smaller records |
| Repeated retransmissions get no response and PMTU is unknown | Back off to a smaller record size |
| Handshake bytes are retransmitted | Preserve the original handshake message bytes |

## Code Behavior

### Timeout Path Can Query a Fallback MTU

In `ssl/d1_lib.cc`, `DTLSv1_handle_timeout` increments the retransmission timeout counter and, after more than `DTLS1_MTU_TIMEOUTS`, queries the BIO for a fallback MTU:

```cpp
ssl->d1->num_timeouts++;
// Reduce MTU after 2 unsuccessful retransmissions.
if (ssl->d1->num_timeouts > DTLS1_MTU_TIMEOUTS &&
    !(SSL_get_options(ssl) & SSL_OP_NO_QUERY_MTU)) {
  long mtu = BIO_ctrl(ssl->wbio.get(), BIO_CTRL_DGRAM_GET_FALLBACK_MTU, 0,
                      nullptr);
  if (mtu >= 0 && mtu <= (1 << 30) && (unsigned)mtu >= dtls1_min_mtu()) {
    ssl->d1->mtu = (unsigned)mtu;
  }
}
```

In `ssl/internal.h`, the timeout threshold is:

```cpp
#define DTLS1_MTU_TIMEOUTS 2
```

This means BoringSSL does have a retransmission-timeout MTU fallback path. The original claim that retransmission never backs off to a smaller record is too broad.

### Retransmission Uses the Current MTU

In `ssl/d1_both.cc`, `send_flight` updates MTU state and allocates the outgoing packet buffer using `ssl->d1->mtu`:

```cpp
dtls1_update_mtu(ssl);

Array<uint8_t> packet;
if (!packet.InitForOverwrite(ssl->d1->mtu)) {
  return -1;
}
```

`seal_next_record` then computes the maximum input length for the current output capacity:

```cpp
size_t max_in_len = dtls_seal_max_input_len(ssl, first_msg.epoch, out.size());
```

It advances through handshake fragments based on the available capacity:

```cpp
size_t capacity = fragments.size() - CBB_len(&cbb);
```

```cpp
ssl->d1->outgoing_offset = range.start + todo;
```

Therefore, if `DTLSv1_handle_timeout` successfully updates `ssl->d1->mtu` to a smaller fallback value, later retransmission can re-fragment the flight into smaller records.

### Backoff Depends on BIO Fallback, Not an Internal Progressive Policy

The fallback logic depends on:

```cpp
BIO_CTRL_DGRAM_GET_FALLBACK_MTU
```

If the BIO does not support that control, or returns an invalid value, the code does not independently reduce the current MTU through a built-in sequence of smaller record sizes.

`dtls1_update_mtu` also queries the BIO for the current MTU or falls back to the default MTU:

```cpp
long mtu = BIO_ctrl(ssl->wbio.get(), BIO_CTRL_DGRAM_QUERY_MTU, 0, nullptr);
if (mtu >= 0 && mtu <= (1 << 30) && (unsigned)mtu >= dtls1_min_mtu()) {
  ssl->d1->mtu = (unsigned)mtu;
} else {
  ssl->d1->mtu = kDefaultMTU;
  BIO_ctrl(ssl->wbio.get(), BIO_CTRL_DGRAM_SET_MTU, ssl->d1->mtu, nullptr);
}
```

Thus BoringSSL satisfies "use a smaller fallback MTU when one is supplied", but not the full autonomous "PMTU unknown, repeated no response, derive smaller record sizes internally" behavior.

## Runner Coverage

`ssl/test/runner/runner.go` registers DTLS retransmission tests:

```go
addDTLSRetransmitTests()
```

In `ssl/test/runner/dtls_tests.go`, there is explicit coverage for retransmission after MTU changes:

```go
name:     "DTLS-Retransmit-ChangeMTU" + suffix,
```

The test manually changes MTU and reads retransmissions:

```go
for i, mtu := range []int{300, 301, 302, 303, 299, 298, 297} {
    c.SetMTU(mtu)
    c.AdvanceClock(useTimeouts[i])
    c.ReadRetransmit()
}
```

In `ssl/test/test_config.cc`, when a runner test provides `-mtu`, the shim disables MTU queries and sets the MTU directly:

```cpp
if (mtu != 0) {
  SSL_set_options(ssl.get(), SSL_OP_NO_QUERY_MTU);
  SSL_set_mtu(ssl.get(), mtu);
}
```

In `ssl/test/packeted_bio.cc`, the packet adapter also changes shim MTU through `SSL_set_mtu`:

```cpp
data->interrupt = [=]() -> bool { return SSL_set_mtu(data->ssl, mtu); };
```

This runner coverage proves that retransmission can adapt when MTU is externally changed. It does not prove that BoringSSL autonomously backs off to progressively smaller records when PMTU is unknown and repeated retransmissions receive no response.

## Runtime Evidence

A linked BoringSSL probe was built and run for this issue.

Probe source:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_pmtu_backoff_probe.cpp
```

CMake target:

```text
repro_dtls13_pmtu_backoff_probe
```

Linked BoringSSL libraries:

```text
D:\project\boringssl-main\build-codex-vs18-msvc\Release\ssl.lib
D:\project\boringssl-main\build-codex-vs18-msvc\Release\crypto.lib
```

Build and run commands:

```powershell
cmake -S D:\project\SpecTrace\test-boringssl\rfc9147\051-100 -B D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe -G "Visual Studio 18 2026" -A x64
cmake --build D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe --config Release --target repro_dtls13_pmtu_backoff_probe
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\build-linked-probe\Release\repro_dtls13_pmtu_backoff_probe.exe
```

Saved log:

```text
D:\project\SpecTrace\test-boringssl\rfc9147\051-100\repro_dtls13_pmtu_backoff_probe.log
```

Observed output:

```text
linked BoringSSL DTLS_method successfully
ok: internal.h contains #define DTLS1_MTU_TIMEOUTS 2
ok: d1_lib.cc contains int DTLSv1_handle_timeout(SSL *ssl)
ok: d1_lib.cc contains ssl->d1->num_timeouts++
ok: d1_lib.cc contains ssl->d1->num_timeouts > DTLS1_MTU_TIMEOUTS
ok: d1_lib.cc contains SSL_OP_NO_QUERY_MTU
ok: d1_lib.cc contains BIO_CTRL_DGRAM_GET_FALLBACK_MTU
ok: d1_lib.cc contains ssl->d1->mtu = (unsigned)mtu
ok: send_flight contains dtls1_update_mtu(ssl)
ok: send_flight contains packet.InitForOverwrite(ssl->d1->mtu)
ok: seal_next_record contains dtls_seal_max_input_len
ok: seal_next_record contains capacity = fragments.size() - CBB_len(&cbb)
ok: seal_next_record contains todo = std::min
ok: seal_next_record contains CBB_add_u24(&cbb, range.start)
ok: seal_next_record contains CBB_add_u24_length_prefixed
ok: seal_next_record contains ssl->d1->outgoing_offset = range.start + todo
ok: runner.go contains addDTLSRetransmitTests()
ok: dtls_tests.go contains DTLS-Retransmit-ChangeMTU
ok: dtls_tests.go contains c.SetMTU(mtu)
ok: dtls_tests.go contains c.ReadRetransmit()
ok: test_config.cc contains SSL_OP_NO_QUERY_MTU
ok: test_config.cc contains SSL_set_mtu
ok: packeted_bio.cc contains SSL_set_mtu(data->ssl, mtu)
RESULT: partial. BoringSSL has a retransmission-timeout path that sets ssl->d1->mtu from BIO_CTRL_DGRAM_GET_FALLBACK_MTU after more than two timeouts, and retransmission fragmentation uses the current ssl->d1->mtu. The remaining gap is that, when PMTU is unknown and no valid BIO fallback MTU is supplied, the product code does not derive its own progressively smaller record sizes. Runner coverage changes MTU manually via SetMTU/SSL_set_mtu, which exercises retransmission under different MTUs but not autonomous unknown-PMTU backoff.
```

The probe links against BoringSSL, creates a `DTLS_method()` context, and checks product and runner source predicates for timeout fallback, MTU-based fragmentation, and runner MTU-change coverage.

## Inconsistency

| RFC 9147 behavior | BoringSSL behavior |
|---|---|
| Size records according to known PMTU estimates | Implemented through current `ssl->d1->mtu` |
| Re-fragment retransmissions when MTU changes | Implemented when MTU is externally updated or fallback MTU is supplied |
| After repeated no-response retransmissions, back off when PMTU is unknown | Partially implemented through BIO fallback MTU query |
| Derive smaller record sizes when no fallback MTU is supplied | Not implemented |
| Runner verifies retransmission after MTU change | Implemented |
| Runner verifies autonomous unknown-PMTU backoff | Not covered |

The accurate inconsistency is not "BoringSSL has no PMTU retransmission backoff". The precise issue is that BoringSSL's backoff depends on an external BIO fallback MTU and does not include an independent progressive unknown-PMTU backoff strategy.

## Root Cause

BoringSSL delegates PMTU fallback decisions to the datagram BIO. After repeated retransmission timeouts, it asks the BIO for `BIO_CTRL_DGRAM_GET_FALLBACK_MTU`. If that returns a valid smaller MTU, retransmission uses it.

When the BIO cannot provide a fallback MTU, the product code has no internal policy such as:

```text
unknown PMTU
  repeated no-response retransmissions
  choose a smaller conservative record size
  re-fragment the handshake flight
  continue with smaller retransmissions
```

The fragmentation machinery exists. The autonomous unknown-PMTU decision policy is the missing part.

## Impact

This is a DTLS retransmission robustness and protocol-conformance issue.

| Impact area | Description |
|---|---|
| Loss recovery | If a path silently drops oversized datagrams and no fallback MTU is supplied, retransmissions may continue at the same size. |
| Interoperability | Peers behind smaller PMTU paths may take longer to complete or fail if no external MTU signal is available. |
| Protocol conformance | The RFC 9147 SHOULD-level unknown-PMTU backoff behavior is only partially implemented. |
| Test coverage | Existing runner tests cover manual MTU changes, not automatic unknown-PMTU backoff. |

This report does not demonstrate memory corruption or code execution. The issue is best characterized as incomplete autonomous PMTU backoff behavior.

## Suggested Fix

To fully cover the RFC 9147 PMTU backoff scenario, BoringSSL should add an internal fallback policy for the case where PMTU is unknown and `BIO_CTRL_DGRAM_GET_FALLBACK_MTU` does not return a valid smaller value.

| Required change | Expected effect |
|---|---|
| Track repeated no-response retransmissions with unknown PMTU | Identifies the RFC 9147 backoff condition |
| Define conservative fallback record sizes | Allows progress without BIO-provided fallback MTU |
| Reduce `ssl->d1->mtu` or per-flight record size after the threshold | Causes subsequent retransmission to fragment smaller |
| Preserve handshake message bytes | Maintains RFC 9147 retransmission correctness |
| Add runner coverage without manual `SetMTU` | Tests autonomous unknown-PMTU backoff |
