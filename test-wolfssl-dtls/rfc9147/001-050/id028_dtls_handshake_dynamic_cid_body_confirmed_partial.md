# DTLSHandshake Dynamic CID Body Branches Are Incomplete

## Summary

wolfSSL implements the normal TLS 1.3 handshake message dispatcher used by DTLS 1.3, including ClientHello, ServerHello, CertificateRequest, Certificate, CertificateVerify, Finished, NewSessionTicket, and KeyUpdate. The DTLS 1.3-specific dynamic CID handshake body alternatives are missing.

## Standard Requirement

Standard: [RFC 9147](https://www.rfc-editor.org/rfc/rfc9147)

Relevant section: `5.7 Handshake Protocol`

Relevant original English text from the standard:

```text
select (msg_type) {
    case client_hello:          ClientHello;
    case server_hello:          ServerHello;
    case end_of_early_data:     EndOfEarlyData;
    case encrypted_extensions:  EncryptedExtensions;
    case certificate_request:   CertificateRequest;
    case certificate:           Certificate;
    case certificate_verify:    CertificateVerify;
    case finished:              Finished;
    case new_session_ticket:    NewSessionTicket;
    case key_update:            KeyUpdate;
    case request_connection_id: RequestConnectionId;
    case new_connection_id:     NewConnectionId;
} body;
```

The requirement is a complete body selection for DTLSHandshake message types.

## Relevant Source Code

`wolfssl-master/wolfssl/internal.h:6644`

```c
enum HandShakeType {
    client_hello         =   1,
    server_hello         =   2,
    session_ticket       =   4,
    end_of_early_data    =   5,
    encrypted_extensions =   8,
    certificate          =  11,
    certificate_request  =  13,
    certificate_verify   =  15,
    finished             =  20,
    key_update           =  24,
};
```

`wolfssl-master/src/tls13.c:13174`

```c
switch (type) {
    case server_hello:
    case encrypted_extensions:
    case certificate_request:
    case session_ticket:
    case client_hello:
    case end_of_early_data:
    case certificate:
    case certificate_verify:
    case finished:
    case key_update:
        ...
}
```

The dispatcher covers the ordinary TLS 1.3 handshake bodies but has no dynamic CID branch.

## Implementation Behavior

Implemented part:

```text
DTLS/TLS 1.3 handshake framing
normal TLS 1.3 handshake type parsing and state checks
post-handshake KeyUpdate and NewSessionTicket processing
static connection_id extension and DTLS 1.3 CID record-layer handling
```

Missing part:

```text
request_connection_id HandShakeType
new_connection_id HandShakeType
RequestConnectionId parser/serializer
NewConnectionId parser/serializer
dispatch from DTLSHandshake.body to those structures
```

## Inconsistency Reason

The standard body select is wider than wolfSSL's dispatcher. wolfSSL satisfies the common TLS 1.3 handshake alternatives but not the DTLS 1.3 dynamic CID alternatives, so the requirement is partially satisfied rather than fully satisfied.

## Runtime Evidence

Runtime command run from `wolfssl-master`:

```text
..\build\wolfssl-dtls13-audit-tests\tests\unit.test.exe -test_dtls13_basic_connection_id -test_wolfSSL_dtls_cid_parse
```

Relevant log: `phase2_wolfssl_builtin_dtls13_tests.log`

Static dynamic-CID symbol check:

```text
rg -n "request_connection_id|new_connection_id|cid_immediate|cid_spare|RequestConnectionId|NewConnectionId|ConnectionIdUsage|too_many_cids_requested" wolfssl-master\src wolfssl-master\wolfssl wolfssl-master\tests
```

Relevant log: `phase2_dynamic_cid_symbol_check.log`

Result:

```text
No matches found.
```

## Impact

A DTLS 1.3 peer using dynamic CID handshake messages has no matching parser or state machine in wolfSSL, even though normal DTLS 1.3 handshakes and static CID records can work.

## Fix Direction

Add the missing handshake type values, message structures, parser/serializer functions, state validation, ACK interaction, and tests that feed RequestConnectionId and NewConnectionId through the DTLS 1.3 handshake receive/send paths.
