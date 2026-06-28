# Option Repeatability And Code-Context Validation Gaps

## Summary     

libcoap implements option length checks and a global repeatability table, but RFC 7252 has context-dependent rules: extra occurrences of non-repeatable options must be treated like unrecognized options, options not defined for a method or response code must not be sent, recipients must treat them as unrecognized, and ETag is repeatable in requests but not more than once in responses.

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252), Sections 5.4.1, 5.4.5, and 5.10.6.

Relevant original English text:

```text
If a message includes an option with more occurrences than the option is defined for, each supernumerary option occurrence that appears subsequently in the message MUST be treated like an unrecognized option.
```

```text
In case an option is not defined for a Method or Response Code, it MUST NOT be included by a sender and MUST be treated like an unrecognized option by a recipient.
```

```text
The ETag Option MUST NOT occur more than once in a response.
```

## Relevant Source Code

`libcoap-develop/src/coap_pdu.c` defines repeatability globally. `COAP_OPTION_ETAG` is always allowed as repeatable, without checking whether the PDU is a request or response.

```c
int
coap_option_check_repeatable(coap_option_num_t number) {
  /* Validate that the option is repeatable */
  switch (number) {
  /* Ignore list of genuine repeatable */
  case COAP_OPTION_IF_MATCH:
  case COAP_OPTION_ETAG:
  case COAP_OPTION_LOCATION_PATH:
  case COAP_OPTION_URI_PATH:
```

The receive-side duplicate handling checks repeatability, but does not re-run the supernumerary occurrence through the complete unrecognized-option semantics.

```c
if (last_number == opt_iter.number) {
  /* Check for duplicated option RFC 5272 5.4.5 */
  if (!coap_option_check_repeatable(opt_iter.number)) {
    if (coap_option_filter_get(&ctx->known_options, opt_iter.number) <= 0) {
      ok = 0;
      if (coap_option_filter_set(unknown, opt_iter.number) == 0) {
        goto overflow;
      }
    }
  }
}
```

`libcoap-develop/src/coap_pdu.c` validates option lengths by option number, not by Method or Response Code.

```c
static int
coap_pdu_parse_opt_base(coap_pdu_t *pdu, uint16_t len) {
  int res = 1;

  switch (pdu->max_opt) {
  case COAP_OPTION_IF_MATCH:
    if (len > 8)
      res = 0;
    break;
```

## Runtime / Probe Result

The phase 2 probe confirmed these code-context gaps.

```text
Duplicate option semantics probe: PASS - duplicates are checked by repeatability, not fully reclassified as unrecognized occurrences
Option applicability probe: PASS - base option validation does not branch on Method or Response Code
Response ETag cardinality probe: PASS - ETag is globally repeatable without response-specific cardinality
```

## Runtime Reproduction

Repro file:

- `test-libcoap/201-250/repro_id233_dual_etag_runtime.c`

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id233_dual_etag_runtime.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id233_dual_etag_runtime.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Observed runtime output:

```text
direct_case ok=1 code=69 payload=dual-etag-response etag_count=2 etags=01,02
```

### 1. Direct Dual-ETag Response Acceptance

The repro starts a local malicious/test CoAP server that returns:

- `2.05 Content`
- `ETag: 01`
- `ETag: 02`
- payload `dual-etag-response`

Observed result:

- the libcoap client accepted the response
- the application-visible option iteration path exposed both response ETags
- no parse rejection or "treat second one like unrecognized option" behavior
  occurred on this direct receive path

This is a direct runtime confirmation that the RFC-forbidden
"response contains more than one ETag" case is accepted by libcoap's client
receive path and is surfaced to the application unchanged.

Related proxy/cache stale-replay result:

- `test-libcoap/201-250/id233_proxy_cache_stale_reuse_from_dual_etag_context.md`
  documents the separate runtime chain where a libcoap proxy observe-cache
  replayed stale content and exposed only one downstream ETag from a
  dual-ETag context

## Inconsistency Reason

The RFC rules are not purely option-number rules. They depend on occurrence count, option class, Method, Response Code, and whether the PDU is a request or response. libcoap's validation model is mostly option-number and length based. That leaves response-specific and code-specific invalid options accepted by generic PDU paths.

## Impact

Applications can construct or accept CoAP messages that violate the option tables in RFC 7252. The most concrete case here is a response with more than one ETag option, which the RFC forbids but the global repeatability table allows.

The runtime boundary is now clearer:

- **direct client acceptance:** confirmed
- **application exposure of both response ETags on direct receive:** confirmed
- **proxy/cache consequences:** tracked separately in
  `id233_proxy_cache_stale_reuse_from_dual_etag_context.md`

So this issue is no longer just a theoretical parser-validation mismatch. The
direct receive path accepts and exposes the RFC-forbidden response form to the
application instead of rejecting it or reclassifying the supernumerary ETag as
unrecognized.
