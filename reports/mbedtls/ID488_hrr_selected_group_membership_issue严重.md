# mbedTLS Accepts an HRR `selected_group` Not Advertised in the Original `supported_groups`

## 1. Summary

This issue concerns the TLS 1.3 HelloRetryRequest (HRR) `key_share.selected_group` validation on the client side.

The core mismatch is:

- TLS 1.3 requires the client to reject an HRR if `selected_group` was not present in the original ClientHello `supported_groups` extension.
- mbedTLS has code intended to perform this check.
- However, the ECDHE membership condition appears reversed: it treats a group that is not equal to `selected_group` as evidence that `selected_group` was found.

As a result, a malicious or non-conformant server can send an HRR requesting a group that the client did not advertise in `supported_groups`, and mbedTLS may still generate the second ClientHello using that group.

This is the issue described in this document.

## 2. RFC Original Text

From [RFC 8446, Section 4.2.8](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8):

```text
   selected_group:  The mutually supported group the server intends to
      negotiate and is requesting a retried ClientHello/KeyShare for.
```

The client-side validation rule is defined in [RFC 8446, Section 4.2.8](https://www.rfc-editor.org/rfc/rfc8446#section-4.2.8):

```text
   Upon receipt of this extension in a HelloRetryRequest, the client
   MUST verify that (1) the selected_group field corresponds to a group
   which was provided in the "supported_groups" extension in the
   original ClientHello and (2) the selected_group field does not
   correspond to a group which was provided in the "key_share" extension
   in the original ClientHello.
```

The failure behavior is also mandatory:

```text
   If either of these checks fails, then
   the client MUST abort the handshake with an "illegal_parameter"
   alert.
```

So the required logic is:

- `selected_group` must be in the original `supported_groups`
- `selected_group` must not already be in the original `key_share`
- otherwise, abort with `illegal_parameter`

## 3. Expected HRR Behavior

A valid HRR is not forbidden from asking the client to send a different key share. That is the purpose of HRR.

The valid case looks like this:

```text
ClientHello1:
  supported_groups = [secp256r1, secp384r1]
  key_share        = [secp256r1]

HelloRetryRequest:
  selected_group   = secp384r1

ClientHello2:
  supported_groups = [secp256r1, secp384r1]
  key_share        = [secp384r1]
```

This is valid because `secp384r1` was already advertised in the original `supported_groups`.

The invalid case is:

```text
ClientHello1:
  supported_groups = [secp256r1]
  key_share        = [secp256r1]

HelloRetryRequest:
  selected_group   = secp384r1
```

This HRR must be rejected, because `secp384r1` was not provided in the original `supported_groups`.

## 4. Relevant mbedTLS Code

### 4.1 HRR `selected_group` parsing

The relevant function is `ssl_tls13_parse_hrr_key_share_ext()` in [ssl_tls13_client.c](../mbedtls-development/library/ssl_tls13_client.c:376).

The comments describe the RFC requirement:

```c
/* Upon receipt of this extension in a HelloRetryRequest, the client
 * MUST first verify that the selected_group field corresponds to a
 * group which was provided in the "supported_groups" extension in the
 * original ClientHello.
 */
```

Relevant lines:

- [ssl_tls13_client.c:397](../mbedtls-development/library/ssl_tls13_client.c:397)
- [ssl_tls13_client.c:399](../mbedtls-development/library/ssl_tls13_client.c:399)

### 4.2 The membership check is suspicious

The implementation then iterates over `ssl->conf->group_list`:

```c
for (; *group_list != 0; group_list++) {
#if defined(PSA_WANT_ALG_ECDH)
    if (mbedtls_ssl_tls13_named_group_is_ecdhe(*group_list)) {
        if ((mbedtls_ssl_get_psa_curve_info_from_tls_id(
                 *group_list, NULL, NULL) == PSA_ERROR_NOT_SUPPORTED) ||
            *group_list != selected_group) {
            found = 1;
            break;
        }
    }
#endif
```

Relevant lines:

- [ssl_tls13_client.c:406](../mbedtls-development/library/ssl_tls13_client.c:406)
- [ssl_tls13_client.c:409](../mbedtls-development/library/ssl_tls13_client.c:409)
- [ssl_tls13_client.c:411](../mbedtls-development/library/ssl_tls13_client.c:411)
- [ssl_tls13_client.c:412](../mbedtls-development/library/ssl_tls13_client.c:412)

The suspicious condition is:

```c
*group_list != selected_group
```

For a membership check, the expected condition should be based on equality:

```c
*group_list == selected_group
```

Instead, the current code sets `found = 1` when it encounters an ECDHE group that is not equal to `selected_group`.

### 4.3 Alert path depends on `found == 0`

After the loop, mbedTLS raises an alert only if `found == 0`, or if the selected group was already offered in the original key share:

```c
if (found == 0 || selected_group == ssl->handshake->offered_group_id) {
    MBEDTLS_SSL_PEND_FATAL_ALERT(
        MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER,
        MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER);
    return MBEDTLS_ERR_SSL_ILLEGAL_PARAMETER;
}
```

Relevant lines:

- [ssl_tls13_client.c:432](../mbedtls-development/library/ssl_tls13_client.c:432)
- [ssl_tls13_client.c:434](../mbedtls-development/library/ssl_tls13_client.c:434)

Therefore, if the reversed membership condition incorrectly sets `found = 1`, the `illegal_parameter` path is bypassed.

### 4.4 The invalid group is remembered for ClientHello2

If the alert path is bypassed, mbedTLS records the HRR-selected group:

```c
ssl->handshake->offered_group_id = selected_group;
```

Relevant line:

- [ssl_tls13_client.c:441](../mbedtls-development/library/ssl_tls13_client.c:441)

When writing the second ClientHello, mbedTLS uses this value:

```c
group_id = ssl->handshake->offered_group_id;
```

Relevant line:

- [ssl_tls13_client.c:287](../mbedtls-development/library/ssl_tls13_client.c:287)

So an invalid HRR `selected_group` can directly determine the key share generated in ClientHello2.

### 4.5 Later ServerHello processing only checks against `offered_group_id`

When parsing the ServerHello `key_share`, mbedTLS checks that the server's group matches `ssl->handshake->offered_group_id`:

```c
offered_group = ssl->handshake->offered_group_id;
if (offered_group != group) {
    MBEDTLS_SSL_PEND_FATAL_ALERT(MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE,
                                 MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE);
    return MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE;
}
```

Relevant lines:

- [ssl_tls13_client.c:482](../mbedtls-development/library/ssl_tls13_client.c:482)
- [ssl_tls13_client.c:483](../mbedtls-development/library/ssl_tls13_client.c:483)

This means that, after `offered_group_id` has been overwritten by the HRR value, the later ServerHello check does not re-check whether the group was in the original `supported_groups`.

## 5. Dynamic Test Result

The reproduction script is [runtime_retest_id488_hrr_selected_group.py](runtime_retest_id488_hrr_selected_group.py:1).

The test runs an mbedTLS TLS 1.3 client with only one configured group:

```text
groups=secp256r1
```

The test server then sends a crafted HRR with:

```text
selected_group = secp384r1
```

This is invalid because `secp384r1` was not in the original ClientHello `supported_groups`.

Observed result:

```text
ch1_supported_groups: [23]
ch1_key_share_groups: [23]
selected_group ( 24 )
verdict: accepted_sent_second_clienthello
ch2_supported_groups: [23]
ch2_key_share_groups: [24]
```

The group IDs are:

- `23` = `secp256r1`
- `24` = `secp384r1`

So the observed behavior is:

```text
ClientHello1:
  supported_groups = [secp256r1]
  key_share        = [secp256r1]

HelloRetryRequest:
  selected_group   = secp384r1

ClientHello2:
  supported_groups = [secp256r1]
  key_share        = [secp384r1]
```

The client did not abort with `illegal_parameter`. Instead, it accepted the HRR and generated a second ClientHello using `secp384r1`.

## 6. Why This Is Inconsistent with the Specification

The RFC requires `selected_group` to be a group from the original ClientHello `supported_groups`.

In the reproduced case:

```text
original supported_groups = [secp256r1]
HRR selected_group        = secp384r1
```

The required result is:

```text
abort with illegal_parameter
```

The observed result is:

```text
send ClientHello2 with key_share = secp384r1
```

The inconsistency is caused by the membership check:

```c
*group_list != selected_group
```

This condition can set `found = 1` merely because the configured list contains some other ECDHE group. It does not prove that `selected_group` is a member of the original `supported_groups`.

## 7. Impact

The immediate impact is standards non-compliance in HRR processing.

The client can be driven into a state where its second ClientHello is internally inconsistent:

```text
supported_groups = [secp256r1]
key_share        = [secp384r1]
```

If the peer continues the handshake using `secp384r1`, later mbedTLS checks compare the ServerHello key share against `offered_group_id`, which has already been overwritten to `secp384r1`. Therefore, the implementation may continue along the `secp384r1` path instead of rejecting the HRR at the required point.

The issue is not that HRR itself is wrong. HRR is valid when the selected group was advertised in `supported_groups` but not sent in `key_share`. The issue is that mbedTLS accepts an HRR-selected group that was not advertised in `supported_groups`.

## 8. Conclusion

mbedTLS partially implements the TLS 1.3 HRR `selected_group` checks, but the ECDHE membership logic is inconsistent with the RFC requirement.

The RFC-mandated condition is:

```text
selected_group must be in original supported_groups
```

The observed mbedTLS behavior allows:

```text
selected_group not in original supported_groups
```

and proceeds to generate a second ClientHello using that group.

