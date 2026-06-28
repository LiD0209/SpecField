# Location-Path Dot Segment Validation Is Only Partially Enforced

## Summary

libcoap validates only the raw length of `Location-Path` option values. It does not reject `.` or `..` when an application constructs a response with low-level APIs such as `coap_add_option()`, and it does not reject those values when a consumer parses a received response PDU.

That makes this more than a formatting mismatch:

- an invalid `Location-Path` can be emitted onto the wire unchanged
- another libcoap-based consumer can parse and expose it unchanged
- a downstream naive client that treats `Location-Path` as ordinary path segments can normalize into a different resource and auto-follow into `/users/admin`, `/admin`, or `/config`

## Standard Reference

CoAP standard: [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252), Section 5.10.7, "Location-Path and Location-Query".

Relevant original English text:

```text
The value of a Location-Path Option MUST NOT be "." or "..".
```

## Relevant Source Code

`libcoap-develop/src/coap_pdu.c` checks only the maximum raw length for `Location-Path`:

```c
case COAP_OPTION_LOCATION_PATH:
  if (len > 255)
    res = 0;
  break;
```

The URI helper code in `libcoap-develop/src/coap_uri.c` does know about dot segments:

```c
/* returns 1 if . , 2 if .. else 0. */
static int
dots(const uint8_t *s, size_t len) {
```

but that logic is helper-side normalization, not generic raw `Location-Path` validation. A manually built response or a received PDU can therefore bypass that helper path entirely.

## Runtime Evidence

### Phase 2 Probe

The existing phase 2 check already showed that the raw parser only length-checks:

```text
Location-Path raw option validation probe: PASS - raw parser only length-checks and has no dot-segment rejection
```

### End-to-End Chain Reproduction

Repro file:

- `test-libcoap/201-250/repro_id207_location_path_traversal.c`

This repro builds a local chain with one malicious server and two client-side interpretations:

1. the server exposes `POST /users/alice/items`
2. on success it returns `2.01 Created`
3. the response is intentionally populated with illegal raw `Location-Path` segments using `coap_add_option()`
4. the client receives the UDP response, parses the response PDU, and records the exact `Location-Path` values that arrived over the network
5. a strict parser rejects any `.` or `..` segment
6. a naive parser appends the received `Location-Path` segments to the request path, normalizes dot segments, and automatically issues a follow-up `GET`
7. the server records which follow-up resource handler was actually hit

The repro uses three traversal-style payloads:

- `..`, `..`, `admin` -> naive follow-up becomes `/users/admin`
- `..`, `..`, `..`, `admin` -> naive follow-up becomes `/admin`
- `..`, `..`, `..`, `config` -> naive follow-up becomes `/config`

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id207_location_path_traversal.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id207_location_path_traversal.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Observed runtime output:

```text
scenario=climb_to_users_admin_get method=GET response_code=2.01 raw_location=../../admin exact_match=1 strict=reject client_policy_allowed_initial_prefix=1 policy_check_mode=pre_normalize_only followup_uri=/users/admin client_policy_allowed_followup=0 policy_bypass=1 handler=users_admin followup_code=69 target_state_before=users-admin-initial target_state_after=users-admin-initial
scenario=climb_to_admin_delete method=DELETE response_code=2.01 raw_location=../../../admin exact_match=1 strict=reject client_policy_allowed_initial_prefix=1 policy_check_mode=pre_normalize_only followup_uri=/admin client_policy_allowed_followup=0 policy_bypass=1 handler=admin followup_code=66 target_state_before=admin-initial target_state_after=<missing>
scenario=climb_to_config_put method=PUT response_code=2.01 raw_location=../../../config exact_match=1 strict=reject client_policy_allowed_initial_prefix=1 policy_check_mode=pre_normalize_only followup_uri=/config client_policy_allowed_followup=0 policy_bypass=1 handler=config followup_code=68 target_state_before=mode=safe target_state_after=danger=1;mode=debug
ID207_CHAIN_PASS: invalid Location-Path reached consumer, bypassed client-side path policy, and triggered unintended follow-up resource access including state-changing writes
```

Interpretation:

- the malicious server successfully emitted invalid `Location-Path` values using low-level libcoap response construction
- the receiving side parsed and exposed those exact `..` segments unchanged
- the strict parser rejected the invalid `Location-Path`
- the naive parser normalized the path and issued follow-up requests against unintended resources
- the client-side policy check was applied only to the original `/users/alice/items/...` request context, not to the normalized follow-up path
- the runtime log shows `client_policy_allowed_initial_prefix=1` together with `followup_uri=/admin` or `followup_uri=/config`, which demonstrates a path traversal-style client-side policy bypass
- the server-side `/admin` and `/config` handlers were not only reached but also had state modified
- in particular, `DELETE /admin` removed the resource and `PUT /config` changed the config state from `mode=safe` to `danger=1;mode=debug`

That shows the issue is not limited to protocol-format noncompliance. It can also create path-semantics pollution in downstream consumers that auto-follow or otherwise operationalize `Location-Path`.

### Proxy / Cache Propagation with libcoap Built-In Proxy Support

Repro file:

- `test-libcoap/201-250/repro_id207_location_path_proxy_cache.c`

This repro uses libcoap's built-in proxy support and its observe-response cache path:

1. an origin server exposes observable `GET /users/alice/items`
2. the origin response carries `Observe` and malicious `Location-Path: .. / .. / .. / config`
3. a libcoap reverse proxy forwards the first client's observe request to the origin
4. libcoap stores the observe response in its proxy response cache
5. a second client issues the same observe request through the same proxy
6. the proxy replays the cached response to the second client without re-hitting the origin resource
7. both clients naively normalize the cached `Location-Path` to `/config`
8. both clients then auto-issue `PUT /config`

Build command:

```text
gcc -ID:\project\conditionFuzzing\libcoap-develop\include -ID:\project\conditionFuzzing\libcoap-develop\include\coap3 -ID:\project\conditionFuzzing\build-libcoap-151-200-lib\include -ID:\project\conditionFuzzing\build-libcoap-151-200-lib -o D:\project\conditionFuzzing\test-libcoap\201-250\repro_id207_location_path_proxy_cache.exe D:\project\conditionFuzzing\test-libcoap\201-250\repro_id207_location_path_proxy_cache.c D:\project\conditionFuzzing\build-libcoap-151-200-lib\libcoap-3.a -lws2_32 -liphlpapi -lwinpthread
```

Observed runtime output:

```text
proxy_cache_case client1_location=../../../config client1_followup_uri=/config client2_location=../../../config client2_followup_uri=/config origin_items_hits=1 config_put_hits=2 final_config=client2=proxy-cache-poison client2_served_from_shared_proxy_cache=1 cross_client_propagation=1
ID207_PROXY_CACHE_PASS: libcoap proxy observe-cache replay propagated invalid Location-Path metadata across clients and both clients performed unintended PUT /config follow-up writes
```

Interpretation:

- the origin `GET /users/alice/items` handler was hit only once, even though two clients received the malicious `Location-Path`
- the second client therefore obtained the invalid `Location-Path` from libcoap's shared proxy observe-cache replay path rather than directly from the origin
- both clients normalized that cached metadata into `/config`
- both clients then performed unintended `PUT /config` writes
- the final config state was overwritten by the second client's propagated follow-up write

This extends the impact from single-client path confusion to metadata poisoning / cross-client propagation through a shared intermediary built on libcoap's own proxy/cache path.

## Inconsistency Reason

RFC 7252 makes the prohibition apply to the option value itself. libcoap's generic raw option path accepts any `Location-Path` value of length 0 to 255 bytes, including `.` and `..`. The URI helper logic is not enough to satisfy the RFC requirement because it is optional application-side processing rather than mandatory raw validation.

As a result:

- a direct `coap_add_option()` caller can emit illegal `Location-Path`
- a received response PDU can carry illegal `Location-Path` to a consumer
- downstream logic may assign unsafe path meaning to that invalid data

## Impact

This is a real protocol-correctness gap with possible downstream security consequences.

If a client stack or application:

- records `Location-Path` as authoritative follow-up state
- appends received `Location-Path` to an existing path context
- normalizes `.` and `..` like ordinary URI segments
- automatically performs follow-up `GET`, `PUT`, or `DELETE`

then an attacker-controlled or noncompliant responder can steer that follow-up away from the expected subtree.

The local chain repro demonstrates concrete examples of three escalation levels:

1. path drift:
   `/users/alice/items` + `.. / .. / admin` -> `/users/admin`
2. client-side policy bypass:
   a client that logged `client_policy_allowed_initial_prefix=1` still followed normalized `/admin`
3. state-changing pollution:
   `/users/alice/items` + `.. / .. / .. / config` -> automatic `PUT /config` that changed server state
4. cross-client propagation:
   a shared libcoap proxy observe-cache replayed the same malicious `Location-Path` to a second client, which then also performed `PUT /config`

So the issue is best described as:

- protocol invalid data can traverse libcoap raw APIs unchanged
- strict consumers can defend by rejecting it
- naive consumers can turn it into path traversal-style follow-up behavior
- that behavior can bypass client-side prefix or resource-scope checks when those checks happen before normalization
- when the follow-up method is state-changing, the impact can become configuration pollution or unintended deletion
- when a shared libcoap proxy observe-cache is in the path, the bad metadata can propagate across multiple clients
