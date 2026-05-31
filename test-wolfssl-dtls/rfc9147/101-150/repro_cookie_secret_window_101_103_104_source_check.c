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
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        failures++;
        return NULL;
    }
    n = ftell(f);
    if (n < 0) {
        fclose(f);
        failures++;
        return NULL;
    }
    rewind(f);
    buf = (char *)malloc((size_t)n + 1);
    if (buf == NULL) {
        fclose(f);
        failures++;
        return NULL;
    }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        printf("FAIL read %s\n", path);
        free(buf);
        fclose(f);
        failures++;
        return NULL;
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
        printf("PASS %-58s contains \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-58s missing \"%s\"\n", name, needle);
        failures++;
    }
}

static void expect_absent(const char *name, const char *text, const char *needle) {
    if (text != NULL && strstr(text, needle) == NULL) {
        printf("PASS %-58s does not contain \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-58s unexpectedly contains \"%s\"\n", name, needle);
        failures++;
    }
}

int main(void) {
    const char *tls13_path =
        "D:\\project\\wolfssl-master\\src\\tls13.c";
    const char *dtls_path =
        "D:\\project\\wolfssl-master\\src\\dtls.c";
    const char *internal_path =
        "D:\\project\\wolfssl-master\\wolfssl\\internal.h";
    const char *tests_path =
        "D:\\project\\wolfssl-master\\tests\\api\\test_tls13.c";

    char *tls13 = read_file(tls13_path);
    char *dtls = read_file(dtls_path);
    char *internal = read_file(internal_path);
    char *tests = read_file(tests_path);
    char *create_cookie;
    char *check_cookie;
    char *send_cookie;
    char *dtls_check;

    if (tls13 == NULL || dtls == NULL || internal == NULL || tests == NULL) {
        return 2;
    }

    create_cookie = slice_between(tls13, "int CreateCookieExt(",
                                  "return TLSX_Cookie_Use");
    check_cookie = slice_between(tls13, "int TlsCheckCookie(",
                                 "return cookieSz;");
    send_cookie = slice_between(tls13, "int wolfSSL_send_hrr_cookie(",
                                "int wolfSSL_disable_hrr_cookie");
    dtls_check = slice_between(dtls, "static int CheckDtlsCookie(",
                               "static int ParseClientHello");

    printf("== Implemented HRR cookie path ==\n");
    expect_contains("single HRR cookie secret field", internal,
                    "buffer          tls13CookieSecret;");
    expect_contains("CreateCookieExt requires the single secret", create_cookie,
                    "ssl->buffers.tls13CookieSecret.buffer");
    expect_contains("CreateCookieExt HMAC key is the single secret", create_cookie,
                    "wc_HmacSetKey(cookieHmac, cookieType,");
    expect_contains("TlsCheckCookie verifies with the same single secret", check_cookie,
                    "ssl->buffers.tls13CookieSecret.buffer");
    expect_contains("TlsCheckCookie rejects bad MAC", check_cookie,
                    "return HRR_COOKIE_ERROR;");
    expect_contains("DTLS ClientHello path calls TlsCheckCookie", dtls_check,
                    "ret = TlsCheckCookie(ssl");
    expect_contains("wolfSSL_send_hrr_cookie enables cookie sending", send_cookie,
                    "ssl->options.sendCookie = 1;");
    expect_contains("wolfSSL unit test corrupts current secret", tests,
                    "test_tls13_hrr_bad_cookie");

    printf("\n== Missing built-in transition-window policy ==\n");
    expect_absent("no previous cookie secret field", internal,
                  "tls13CookieSecretPrev");
    expect_absent("no old cookie secret field", internal,
                  "oldCookieSecret");
    expect_absent("no previous-cookie wording in TLS 1.3 source", tls13,
                  "previous cookie secret");
    expect_absent("no both-secret verification wording", tls13,
                  "both secrets");
    expect_absent("no key identifier wording in cookie verification", check_cookie,
                  "key identifier");
    expect_absent("single-secret setter does not preserve previous secret", send_cookie,
                  "previous");
    expect_contains("single-secret setter frees replaced secret", send_cookie,
                    "XFREE(ssl->buffers.tls13CookieSecret.buffer");

    printf("\n== Missing cookie timestamp/expiration policy ==\n");
    expect_absent("CreateCookieExt has no timestamp", create_cookie, "timestamp");
    expect_absent("CreateCookieExt has no lifetime", create_cookie, "lifetime");
    expect_absent("CreateCookieExt has no expiration", create_cookie, "expiration");
    expect_absent("TlsCheckCookie has no timestamp", check_cookie, "timestamp");
    expect_absent("TlsCheckCookie has no lifetime", check_cookie, "lifetime");
    expect_absent("TlsCheckCookie has no expiration", check_cookie, "expiration");

    printf("\nConclusion: %s\n", failures == 0
        ? "PASS - source behavior confirms IDs 101/103/104 are partially satisfied: single-secret HMAC cookies exist, but no built-in dual-secret window or cookie timestamp/expiration policy was found."
        : "FAIL - one or more source assertions did not match the audited tree.");

    free(create_cookie);
    free(check_cookie);
    free(send_cookie);
    free(dtls_check);
    free(tls13);
    free(dtls);
    free(internal);
    free(tests);
    return failures == 0 ? 0 : 1;
}
