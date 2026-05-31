#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    long n;
    char *buf;

    if (f == NULL) {
        printf("FAIL open %s\n", path);
        failures++;
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    rewind(f);
    buf = (char *)malloc((size_t)n + 1);
    if (buf == NULL) {
        fclose(f);
        failures++;
        return NULL;
    }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        printf("FAIL read %s\n", path);
        failures++;
    }
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static char *slice_between(const char *text, const char *begin, const char *end) {
    const char *b = strstr(text, begin);
    const char *e;
    size_t n;
    char *out;

    if (b == NULL) {
        printf("FAIL missing segment start: %s\n", begin);
        failures++;
        return NULL;
    }
    e = strstr(b, end);
    if (e == NULL) {
        printf("FAIL missing segment end after: %s\n", begin);
        failures++;
        return NULL;
    }
    n = (size_t)(e - b);
    out = (char *)malloc(n + 1);
    if (out == NULL) {
        failures++;
        return NULL;
    }
    memcpy(out, b, n);
    out[n] = '\0';
    return out;
}

static void expect_contains(const char *name, const char *text, const char *needle) {
    if (text != NULL && strstr(text, needle) != NULL) {
        printf("PASS %-66s contains \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-66s missing \"%s\"\n", name, needle);
        failures++;
    }
}

static void expect_absent(const char *name, const char *text, const char *needle) {
    if (text != NULL && strstr(text, needle) == NULL) {
        printf("PASS %-66s does not contain \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-66s unexpectedly contains \"%s\"\n", name, needle);
        failures++;
    }
}

int main(void) {
    char *tls13 = read_file("D:\\project\\wolfssl-master\\src\\tls13.c");
    char *dtls = read_file("D:\\project\\wolfssl-master\\src\\dtls.c");
    char *tests = read_file("D:\\project\\wolfssl-master\\tests\\api\\test_dtls.c");
    char *get_session_id;
    char *send_client_hello;
    char *do_server_hello;
    char *do_client_hello;
    char *send_server_hello;
    char *stateless_hrr;
    char *echo_test;
    char *cross_version_test;

    if (tls13 == NULL || dtls == NULL || tests == NULL) {
        return 2;
    }

    get_session_id = slice_between(tls13, "static void GetTls13SessionId(",
                                   "/* handle generation of TLS 1.3 client_hello");
    send_client_hello = slice_between(tls13, "int SendTls13ClientHello(",
                                      "#if defined(WOLFSSL_DTLS13) && !defined(NO_WOLFSSL_CLIENT)");
    do_server_hello = slice_between(tls13, "int DoTls13ServerHello(",
                                    "int SendTls13ServerHello(");
    do_client_hello = slice_between(tls13, "int DoTls13ClientHello(",
                                    "int SendTls13ServerHello(");
    send_server_hello = slice_between(tls13, "int SendTls13ServerHello(",
                                      "static int SendTls13EncryptedExtensions(");
    stateless_hrr = slice_between(dtls, "ret = CreateCookieExt(",
                                  "dtls13_cleanup:");
    echo_test = slice_between(tests, "int test_dtls13_no_session_id_echo(void)",
                              "int test_dtls13_oversized_cert_chain(void)");
    cross_version_test = tests;

    printf("== Client legacy_session_id generation ==\n");
    expect_contains("cached session ID is written when present", get_session_id,
                    "output[*idx] = ssl->session->sessionIDSz;");
    expect_contains("cached session ID bytes are copied", get_session_id,
                    "XMEMCPY(output + *idx, ssl->session->sessionID");
    expect_contains("otherwise zero-length vector is written", get_session_id,
                    "output[*idx] = 0;");
    expect_contains("DTLS 1.3 disables TLS 1.3 middlebox compatibility mode", send_client_hello,
                    "ssl->options.tls13MiddleBoxCompat = 0;");
    expect_contains("DTLS 1.3 ClientHello calls GetTls13SessionId", send_client_hello,
                    "GetTls13SessionId(ssl, args->output, &args->idx);");

    printf("\n== Server handling of non-empty DTLS 1.3 legacy_session_id ==\n");
    expect_contains("server parses ClientHello session ID length", do_client_hello,
                    "sessIdSz = input[args->idx++];");
    expect_contains("server rejects overlong session ID", do_client_hello,
                    "if (sessIdSz > ID_LEN)");
    expect_contains("DTLS 1.3 server does not store client session ID", do_client_hello,
                    "ssl->session->sessionIDSz = 0;");
    expect_contains("DTLS 1.3 ServerHello writes empty legacy_session_id_echo", send_server_hello,
                    "output[idx++] = 0;");
    expect_contains("stateless HRR path clears session ID", stateless_hrr,
                    "nonConstSSL->session->sessionIDSz = 0;");

    printf("\n== Version policy and tests ==\n");
    expect_contains("TLS 1.3 path rejects different-version resumption", send_client_hello,
                    "Cannot resume with a different protocol version.");
    expect_contains("wolfSSL test covers non-empty legacy_session_id no echo", echo_test,
                    "test_dtls13_no_session_id_echo");
    expect_contains("test forces non-empty legacy_session_id", echo_test,
                    "sess->sessionIDSz = ID_LEN;");
    expect_contains("test sets session before DTLS 1.3 ClientHello", echo_test,
                    "wolfSSL_set_session(ssl_c, sess)");
    expect_contains("test verifies ServerHello echo length is zero", echo_test,
                    "RAN_LEN], 0)");
    expect_contains("test covers DTLS 1.2 session rejected for DTLS 1.3 min", cross_version_test,
                    "wolfSSL_set_session(ssl_c, sess), WOLFSSL_FAILURE");
    expect_absent("no dedicated phrase for pre-DTLS 1.3 cached ID strategy", tls13,
                  "pre-DTLS 1.3");

    printf("\nConclusion: %s\n", failures == 0
        ? "PASS - source behavior shows ID 114 is partially satisfied/partly superseded: wolfSSL can send a cached legacy_session_id in DTLS 1.3 and tests that the server does not echo it, but pre-DTLS-1.3 cross-version session reuse is rejected rather than used as a dedicated cached-ID compatibility strategy."
        : "FAIL - one or more source assertions did not match the audited tree.");

    free(get_session_id);
    free(send_client_hello);
    free(do_server_hello);
    free(do_client_hello);
    free(send_server_hello);
    free(stateless_hrr);
    free(echo_test);
    free(tls13);
    free(dtls);
    free(tests);
    return failures == 0 ? 0 : 1;
}
