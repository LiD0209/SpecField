# Response-Side Unknown Unsafe Option Is Not Mapped To 5.02

## Summary 

libcoap does not convert an upstream response containing an unknown unsafe
option into `5.02 Bad Gateway` for the client. In the tested runtime path, the
client still received the original `2.05` response and also received the
unknown unsafe option itself.

## Covered Test Group

This report covers test group 3:

- response-side unknown unsafe option

Related ID:

- `235`

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252),
Section 5.7.2.

Relevant original English text:

```text
Unsafe options in a response that are not recognized by the CoAP-to-CoAP proxy server MUST lead to a 5.02 (Bad Gateway) response.
```

## Relevant Source Code

In the proxy response path, response options are iterated and generally copied
or consumed, but there is no general conversion step that maps unknown unsafe
upstream response options into `5.02 Bad Gateway`.

```c
coap_option_iterator_init(received, &opt_iter, COAP_OPT_ALL);
while ((option = coap_option_next(&opt_iter))) {
  switch (opt_iter.number) {
  case COAP_OPTION_CONTENT_FORMAT:
    media_type = coap_decode_var_bytes(coap_opt_value(option),
                                       coap_opt_length(option));
    break;
  case COAP_OPTION_MAXAGE:
    maxage = coap_decode_var_bytes(coap_opt_value(option),
                                   coap_opt_length(option));
    break;
```

## Runtime Repro

Repro files:

- `test-libcoap/201-250/repro_id223_232_234_235_237_proxy_runtime.c`
- `test-libcoap/201-250/repro_id223_232_234_235_237_proxy_runtime.exe`

The origin response-side unsafe-option case returns a normal `2.05` response
plus unknown unsafe elective option `34`.

## Observed Runtime Output

```text
CASE3_response_unknown_unsafe client_code=2.05 client_unknown_unsafe=1 client_payload=scenario=3 origin_hits=1 origin_path=a origin_query=<absent> origin_uri_host=<absent> origin_uri_port=<absent> origin_req_unknown_unsafe=0 origin_rsp_unknown_unsafe=1 client_nack=0
```

## Interpretation

Observed result:

- the origin definitely sent the unsafe option: `origin_rsp_unknown_unsafe=1`
- the client still received `2.05`, not `5.02`
- `client_unknown_unsafe=1`, meaning the unsafe option itself reached the client

This is a direct runtime contradiction of the RFC rule. The proxy did not
translate the unprocessable upstream response into `5.02 Bad Gateway`; it
relayed the original success response and the unsafe option instead.

## Inconsistency Reason

libcoap's response forwarding path lacks a general response-side
unknown-unsafe-to-`5.02` mapping step. As a result, the proxy can pass through
an upstream response that it should have rejected on behalf of the client.

## Impact

A client behind such a proxy can receive response metadata that the proxy does
not understand, instead of getting the RFC-required `5.02 Bad Gateway`
failure. This breaks the intended proxy safety boundary for response-side
unsafe options.
