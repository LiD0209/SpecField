# Request-Side Unknown Unsafe Option Is Forwarded By Proxy

## Summary

libcoap does not reliably terminate proxy processing when a proxy request
contains an unknown unsafe elective option. In the tested runtime path, the
proxy forwarded the request upstream instead of returning `4.02 Bad Option`.

## Covered Test Group

This report covers test group 2:

- request-side unknown unsafe option


## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252),
Section 5.7.2.

Relevant original English text:

```text
All options present in a proxy request MUST be processed at the proxy.
```

```text
Unsafe options in a request that are not recognized by the proxy MUST lead to a 4.02 (Bad Option) response being returned by the proxy.
```

## Relevant Source Code

The generic dispatcher has a path for unknown critical options and malformed
request options:

```c
if (oscore_invalid ||
    (!COAP_PDU_IS_SIGNALING(pdu) && coap_option_check_critical(session, pdu, &opt_filter) == 0)) {
  packet_is_bad = 1;
  if (COAP_PDU_IS_REQUEST(pdu)) {
    response =
        coap_new_error_response(pdu, COAP_RESPONSE_CODE(402), &opt_filter);
```

However, this is not a full proxy-specific unsafe-option enforcement path for
unknown unsafe elective options. In the tested proxy forwarding path, the
request can still be forwarded upstream.

## Runtime Repro

Repro files:

- `test-libcoap/201-250/repro_id223_232_234_235_237_proxy_runtime.c`
- `test-libcoap/201-250/repro_id223_232_234_235_237_proxy_runtime.exe`

The request-side unsafe-option case uses unknown unsafe elective option `34`
together with `Proxy-Uri`.

## Observed Runtime Output

```text
CASE2_request_unknown_unsafe client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=2 proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> origin_hits=1 origin_path=a origin_query=<absent> origin_uri_host=<absent> origin_uri_port=<absent> origin_protected_hit=0 origin_req_unknown_unsafe=1 origin_req_unknown_unsafe_value=170 origin_rsp_unknown_unsafe=0 origin_sensitive_action=0 origin_admin_mode=0 client_nack=0
CASE6_request_unknown_unsafe_semantic client_code=2.05 client_unknown_unsafe=0 client_payload=scenario=9 admin-mode=1 proxy_policy_checked=0 proxy_policy_allowed=0 proxy_seen_proxy_uri=<absent> origin_hits=1 origin_path=a origin_query=<absent> origin_uri_host=<absent> origin_uri_port=<absent> origin_protected_hit=0 origin_req_unknown_unsafe=1 origin_req_unknown_unsafe_value=1 origin_rsp_unknown_unsafe=0 origin_sensitive_action=1 origin_admin_mode=1 client_nack=0
```

## Interpretation

Observed result:

- the client received `2.05`, not `4.02`
- `origin_hits=1`
- `origin_req_unknown_unsafe=1`

So the proxy forwarded a request containing an unsafe option it did not
understand, instead of stopping processing and returning `4.02 Bad Option`.

This is stronger than a source-only concern: the origin actually received the
unknown unsafe request option.

### Additional semantic-penetration probe

The harness also defines a stronger runtime case where the origin interprets
the unknown unsafe option as a meaningful extension. In this probe, option `34`
with value `1` acts like an `admin=1` or `bypass=1` style signal at the origin.

Observed result:

- the client still received `2.05`, not `4.02`
- `origin_hits=1`
- `origin_req_unknown_unsafe=1`
- `origin_req_unknown_unsafe_value=1`
- `origin_sensitive_action=1`
- `origin_admin_mode=1`

So this is not just a formal proxy-side validation gap. The proxy forwarded an
unsafe option it did not understand, and the origin interpreted it as an
extension with privileged semantics and changed internal state accordingly.

## Inconsistency Reason

libcoap covers the common unknown-critical request path, but that does not
amount to full RFC-compliant proxy handling for unknown unsafe elective
request options. In the tested forward-dynamic proxy path, the request was
accepted and relayed upstream.

## Impact

A proxy built on this path can forward request-side unsafe options that it does
not understand, exposing the origin to request metadata that should have been
terminated at the proxy boundary with `4.02 Bad Option`. If the origin assigns
meaning to such an extension option, this becomes a real policy blind spot or
unexpected-origin-behavior channel rather than only a conformance issue.
