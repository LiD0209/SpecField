# ID271: OpenSSL unknown extension handling split analysis

## 1. Conclusion

This issue should be analyzed separately for the server side and the client side.

- Server side: when OpenSSL receives unknown extensions in `ClientHello`, it follows the TLS 1.3 compatibility rule and ignores them. This is consistent with RFC 8446.
- Client side: when OpenSSL receives unknown extensions in `ServerHello`, it is strict for recognized extensions, but fully unknown extension types are still admitted by the generic collection logic and are not uniformly rejected at the extension parsing stage. This is weaker than the RFC 8446 `ServerHello` constraint.

Therefore, `ID271` is best classified as `partial`, not `satisfied`.

## 2. Standard English description

### 2.1 Server-side rule: unknown extensions in `ClientHello`

The relevant English text in `TLS1.3.txt` is:

```text
extensions:  Clients request extended functionality from servers by
   sending data in the extensions field.  The actual "Extension"
   format is defined in Section 4.2.  In TLS 1.3, the use of certain
   extensions is mandatory, as functionality has moved into
   extensions to preserve ClientHello compatibility with previous
   versions of TLS.  Servers MUST ignore unrecognized extensions.
```

The key sentence is:

```text
Servers MUST ignore unrecognized extensions.
```

This sentence applies to the server receiving `ClientHello`.

### 2.2 Client-side rule: extension set in `ServerHello`

The relevant English text in `TLS1.3.txt` is:

```text
extensions:  A list of extensions.  The ServerHello MUST only include
   extensions which are required to establish the cryptographic
   context and negotiate the protocol version.  All TLS 1.3
   ServerHello messages MUST contain the "supported_versions"
   extension.  Current ServerHello messages additionally contain
   either the "pre_shared_key" extension or the "key_share"
   extension, or both (when using a PSK with (EC)DHE key
   establishment).  Other extensions (see Section 4.2) are sent
   separately in the EncryptedExtensions message.
```

The core requirement is:

```text
The ServerHello MUST only include extensions which are required to establish the cryptographic context and negotiate the protocol version.
```

The request/response rule in `TLS1.3.txt` is:

```text
Implementations MUST NOT send extension responses if the remote
endpoint did not send the corresponding extension requests, with the
exception of the "cookie" extension in the HelloRetryRequest.  Upon
receiving such an extension, an endpoint MUST abort the handshake
with an "unsupported_extension" alert.
```

And the alert definition says:

```text
unsupported_extension:  Sent by endpoints receiving any handshake
   message containing an extension known to be prohibited for
   inclusion in the given handshake message, or including any
   extensions in a ServerHello or Certificate not first offered in
   the corresponding ClientHello or CertificateRequest.
```

Together, these rules mean that `ServerHello` is not a general "unknown extension can always be ignored" context. It is a tightly constrained response message.

## 3. OpenSSL code strategy

## 3.1 Shared collection logic

In `ssl/statem/extensions.c`, OpenSSL uses a shared extension collector for both directions.

The first important behavior is in `verify_extension()`:

```c
static int verify_extension(SSL_CONNECTION *s, unsigned int context,
    unsigned int type, custom_ext_methods *meths,
    RAW_EXTENSION *rawexlist, RAW_EXTENSION **found)
{
    ...

    /* Unknown extension. We allow it */
    *found = NULL;
    return 1;
}
```

This means that an unknown extension is not rejected immediately. Instead:

- recognized built-in extensions get an internal slot
- registered custom extensions get an internal slot
- unknown extensions are accepted, but `*found` becomes `NULL`

The second important behavior is in `tls_collect_extensions()`:

```c
if (!verify_extension(s, context, type, exts, raw_extensions, &thisex)
    || (thisex != NULL && thisex->present == 1)
    || (type == TLSEXT_TYPE_psk
        && (context & SSL_EXT_CLIENT_HELLO) != 0
        && PACKET_remaining(&extensions) != 0)) {
    SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_EXTENSION);
    goto err;
}

...

if (idx < OSSL_NELEM(ext_defs)
    && (context & (SSL_EXT_CLIENT_HELLO
                   | SSL_EXT_TLS1_3_CERTIFICATE_REQUEST
                   | SSL_EXT_TLS1_3_NEW_SESSION_TICKET)) == 0
    ...
    && (s->ext.extflags[idx] & SSL_EXT_FLAG_SENT) == 0) {
    SSLfatal(s, SSL_AD_UNSUPPORTED_EXTENSION,
        SSL_R_UNSOLICITED_EXTENSION);
    goto err;
}
```

The key boundary is:

- duplicate and unsolicited-response checks are mainly applied to extensions that have been indexed into the built-in table
- fully unknown extensions do not get such a slot
- therefore they do not naturally flow through the same strict built-in rejection path

So the shared collector is fundamentally compatibility-oriented for unknown extension types.

## 3.2 Server-side OpenSSL strategy

The server processes `ClientHello` extensions in `ssl/statem/statem_srvr.c`:

```c
extensions = clienthello->extensions;
if (!tls_collect_extensions(s, &extensions, SSL_EXT_CLIENT_HELLO,
        &clienthello->pre_proc_exts,
        &clienthello->pre_proc_exts_len, 1)) {
    /* SSLfatal already been called */
    goto err;
}
```

Because `ClientHello` uses the shared collector with `SSL_EXT_CLIENT_HELLO`, and because unknown extensions are accepted in `verify_extension()`, the practical strategy is:

- accept the raw extension block
- ignore extension types that are not recognized
- continue handshake processing

This matches the RFC 8446 sentence:

```text
Servers MUST ignore unrecognized extensions.
```

## 3.3 Client-side OpenSSL strategy

The client processes `ServerHello` extensions in `ssl/statem/statem_clnt.c`:

```c
if (!tls_collect_extensions(s, &extpkt,
        SSL_EXT_TLS1_2_SERVER_HELLO
            | SSL_EXT_TLS1_3_SERVER_HELLO,
        &extensions, NULL, 1)) {
    goto err;
}

...

context = SSL_CONNECTION_IS_TLS13(s) ? SSL_EXT_TLS1_3_SERVER_HELLO
                                     : SSL_EXT_TLS1_2_SERVER_HELLO;
if (!tls_validate_all_contexts(s, context, extensions)) {
    SSLfatal(s, SSL_AD_ILLEGAL_PARAMETER, SSL_R_BAD_EXTENSION);
    goto err;
}
```

For recognized extensions, this is strict:

- the extension must be legal for the message context
- the extension must pass request/response and semantic checks
- illegal recognized extensions can trigger `bad_extension`, `illegal_parameter`, or `unsupported_extension`

But for fully unknown extension types, the path is weaker:

- `verify_extension()` still allows them
- they do not get a normal indexed slot
- `tls_validate_all_contexts()` only iterates over collected indexed extensions
- the built-in unsolicited check is tied to built-in extension indexing

So the client-side strategy is effectively:

- strict for recognized `ServerHello` extensions
- compatibility-oriented for fully unknown `ServerHello` extension types

That is exactly why this item is not `satisfied`.

## 4. Tests we performed

## 4.1 Server-side test: unknown extension in `ClientHello`

We already had runtime evidence in `runtime_retest/id252_unknown_extension_runtime/`.

The server log shows that OpenSSL server received an unknown client extension:

```text
TLS client extension "unknown" (id=65000), len=0
...
SSL_accept:SSLv3/TLS read client hello
SSL_accept:SSLv3/TLS write server hello
...
SSL_accept:SSLv3/TLS write finished
```

The client log shows that the handshake still completed:

```text
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
DONE
```

This test supports the conclusion that OpenSSL server ignores unknown `ClientHello` extensions, which is consistent with RFC 8446.

## 4.2 Client-side test: unknown extension in `ServerHello`

For the client side, we built a runtime test in `runtime_retest/id271_serverhello_unknown_runtime/`.

The test idea was:

1. use a local proxy to modify the first `ClientHello`
2. inject a previously absent empty extension type `0x1234`
3. let the server echo the same extension in `ServerHello`
4. observe whether the OpenSSL client rejects it at `ServerHello` parsing time

The proxy script used for the test was:

```python
UNKNOWN_EXT = b"\\x12\\x34\\x00\\x00"

...

patched, injected = inject_unknown_extension_into_clienthello(buf)
server.sendall(patched)
log(f"injected_unknown_ext={1 if injected else 0}")
```

The proxy log confirms that the extension injection really happened:

```text
proxy_listen=127.0.0.1:44341
client_connected=127.0.0.1:51616
server_connected=127.0.0.1:44340
injected_unknown_ext=1
proxy_done=1
```

The client runtime log shows that the resulting `ServerHello` really contained the unknown extension:

```text
<<< TLS 1.3, Handshake [length 04be], ServerHello
...
28 50 e9 da de 21 39 13 02 00 04 72 12 34 00 00
00 2b 00 02 03 04 00 33 ...
```

Here, `12 34 00 00` is exactly the injected empty extension.

The important observation is that the client did **not** immediately fail with `unsupported_extension` or `illegal_parameter` at the `ServerHello` extension parsing step.

Instead, the later failure was:

```text
>>> TLS 1.3, Alert [length 0002], fatal bad_record_mac
SSL3 alert write:fatal:bad record mac
```

This later `bad_record_mac` is expected in this proxy experiment, because the proxy changed the original `ClientHello`, which changes the handshake transcript and eventually breaks authenticated record processing.

So this client-side test does not mean "the entire handshake succeeds with unknown `ServerHello` extensions". What it does show is:

- the unknown extension was really present in `ServerHello`
- the client did not uniformly reject it at the `ServerHello` extension validation stage
- the failure happened later for transcript/authentication reasons

That is strong evidence for a compatibility-oriented unknown-extension path on the client side.

## 5. Why the inconsistency exists

The mismatch comes from three layers.

### 5.1 RFC 8446 is asymmetric

The standard treats the two directions differently:

- server receiving `ClientHello`: ignore unknown extensions
- client receiving `ServerHello`: only a narrow set of extensions is allowed, and unsolicited responses should be aborted

So the standard is intentionally not symmetric here.

### 5.2 OpenSSL uses a shared generic collector

OpenSSL reuses one generic extension collection framework for both sides. That framework is intentionally permissive for unknown extension types:

```c
/* Unknown extension. We allow it */
```

This makes server-side compatibility easy, but it also means client-side `ServerHello` handling inherits part of the same permissive behavior.

### 5.3 Strictness is centered on recognized extensions

OpenSSL's strong checks are table-driven:

- recognized built-in extensions
- registered custom extensions

Unknown extension types sit outside that indexed structure. As a result:

- recognized illegal extensions are rejected strictly
- fully unknown extension types do not always hit the same strict rejection path

So the implementation is not "strict for all `ServerHello` extensions". It is "strict for recognized `ServerHello` extensions, compatibility-oriented for unknown ones".

## 6. Final assessment

`ID271` should remain `partial`.

The reason is not that OpenSSL mishandles both sides equally. The split view is:

- server side: behavior is consistent with TLS 1.3
- client side: behavior is only partially consistent, because unknown `ServerHello` extensions are not uniformly rejected at the extension parsing stage

Therefore the real issue is client-side compatibility relaxation, not a symmetric server/client bug.
