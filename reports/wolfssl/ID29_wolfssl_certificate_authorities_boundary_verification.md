# wolfSSL certificate_authorities Length-Boundary Verification

## Scope
This note verifies whether wolfSSL truly has the `certificate_authorities` extension length-boundary issue.

## RFC baseline
From `TLS1.3.txt` (RFC 8446 presentation language):

- `opaque DistinguishedName<1..2^16-1>;`
- `opaque authorities<3..2^16-1>;`
- `struct { opaque authorities<3..2^16-1>; } CertificateAuthoritiesExtension;`

So the CA list payload must not be shorter than 3 bytes (before counting the outer extension header).

## Build-dependent behavior

### Default build (`build/wolfssl-default`)

- `OPENSSL_EXTRA` is not enabled in this build (`options.h` shows it undefined).
- In `internal.h`, CA Names support is gated and `WOLFSSL_NO_CA_NAMES` is set when `OPENSSL_EXTRA` is not enabled.
- Therefore, `certificate_authorities` semantic parsing is not active in this build.

Observed probe results:

- `size=2` -> `ret=-328` (`BUFFER_ERROR`)
- `size=3` -> `ret=0`
- `size=4` -> `ret=0`
- `size=6` -> `ret=0`

Interpretation: after generic extension framing checks, this extension is effectively treated as unsupported/unknown in default build (except the generic minimum-size guard path catches `size=2`).

### OpenSSL-enabled build (`build/wolfssl-openssl`)

Probe results:

- `size=2` -> `ret=-328` (`BUFFER_ERROR`)
- `size=3` -> `ret=-328` (`BUFFER_ERROR`)
- `size=4` -> `ret=-132` (`BUFFER_E`)
- `size=6` (DN=`30 00`) -> `ret=0`

Interpretation: when CA Names feature is enabled, malformed short payloads are rejected; the reported low-boundary problem is **not reproduced** in this build.

## Code evidence

- Generic extension minimum-size check: `src/tls.c` (`TLSX_Parse`) enforces `size < TLSX_GET_MIN_SIZE_CLIENT(...)` rejection.
- CA extension parser path: `src/tls.c` (`TLSX_CA_Names_Parse`) validates length framing and per-entry boundaries.
- Feature gate: `wolfssl/internal.h` CA Names macros tie support to `OPENSSL_EXTRA`.

## Verdict

For wolfSSL, this is primarily **configuration-dependent behavior**, not a confirmed universal parser boundary bug:

- In OpenSSL-enabled CA Names build: boundary violation was not reproduced.
- In default build: CA Names path is not active, so this is better classified as feature-gated/non-covered behavior.
