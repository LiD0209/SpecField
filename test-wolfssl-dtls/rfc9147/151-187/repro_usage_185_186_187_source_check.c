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
        printf("PASS %-68s contains \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-68s missing \"%s\"\n", name, needle);
        failures++;
    }
}

static void expect_absent(const char *name, const char *text, const char *needle) {
    if (text != NULL && strstr(text, needle) == NULL) {
        printf("PASS %-68s does not contain \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-68s unexpectedly contains \"%s\"\n", name, needle);
        failures++;
    }
}

int main(void) {
    char *internal = read_file("D:\\project\\wolfssl-master\\wolfssl\\internal.h");
    char *dtls = read_file("D:\\project\\wolfssl-master\\src\\dtls.c");
    char *dtls13 = read_file("D:\\project\\wolfssl-master\\src\\dtls13.c");
    char *tls13 = read_file("D:\\project\\wolfssl-master\\src\\tls13.c");
    char *tests = read_file("D:\\project\\wolfssl-master\\tests\\api\\test_dtls.c");
    char *cid_info;
    char *handshake_enum;
    char *dispatcher;
    char *cid_parse;
    char *cid_set;
    char *dtls13_cid;

    if (internal == NULL || dtls == NULL || dtls13 == NULL ||
            tls13 == NULL || tests == NULL) {
        return 2;
    }

    cid_info = slice_between(internal, "typedef struct CIDInfo {",
                             "} CIDInfo;");
    handshake_enum = slice_between(internal, "enum HandShakeType {",
                                   "};");
    dispatcher = slice_between(tls13, "int DoTls13HandShakeMsgType(",
                               "#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_ASYNC_IO)");
    cid_parse = slice_between(dtls, "int TLSX_ConnectionID_Parse(",
                              "void DtlsCIDOnExtensionsParsed(");
    cid_set = slice_between(dtls, "int wolfSSL_dtls_cid_set(",
                            "int wolfSSL_dtls_cid_get_rx_size(");
    dtls13_cid = slice_between(dtls13, "static int Dtls13AddCID(",
                               "#else\n#define Dtls13AddCID");

    printf("== Implemented static CID support ==\n");
    expect_contains("CIDInfo has tx CID pointer", cid_info, "ConnectionID* tx;");
    expect_contains("CIDInfo has rx CID pointer", cid_info, "ConnectionID* rx;");
    expect_contains("CIDInfo stores negotiated bit", cid_info, "byte negotiated : 1;");
    expect_contains("connection_id extension parser exists", dtls,
                    "int TLSX_ConnectionID_Parse(");
    expect_contains("DTLS 1.3 unified header can add CID", dtls13_cid,
                    "*flags |= DTLS13_CID_BIT;");
    expect_contains("DTLS 1.3 unified header checks received CID", dtls13_cid,
                    "DtlsCIDCheck(ssl");
    expect_contains("static DTLS 1.3 CID API test exists", tests,
                    "test_dtls13_basic_connection_id");

    printf("\n== Missing dynamic CID update message types ==\n");
    expect_absent("no request_connection_id handshake enum", handshake_enum,
                  "request_connection_id");
    expect_absent("no new_connection_id handshake enum", handshake_enum,
                  "new_connection_id");
    expect_absent("no RequestConnectionId symbol", internal, "RequestConnectionId");
    expect_absent("no NewConnectionId symbol", internal, "NewConnectionId");
    expect_absent("dispatcher has no request_connection_id case", dispatcher,
                  "case request_connection_id");
    expect_absent("dispatcher has no new_connection_id case", dispatcher,
                  "case new_connection_id");

    printf("\n== Missing usage semantics and response state machine ==\n");
    expect_absent("no ConnectionIdUsage enum", internal, "ConnectionIdUsage");
    expect_absent("no cid_spare usage", internal, "cid_spare");
    expect_absent("no cid_immediate usage", internal, "cid_immediate");
    expect_absent("no num_cids field", internal, "num_cids");
    expect_absent("no cid_spare in source", tls13, "cid_spare");
    expect_absent("no cid_immediate in source", tls13, "cid_immediate");
    expect_absent("no RequestConnectionId response code", tls13, "RequestConnectionId");
    expect_absent("no dynamic CID update tests", tests, "RequestConnectionId");
    expect_absent("no usage tests", tests, "cid_immediate");

    printf("\n== Static-only behavior rejects in-connection CID changes ==\n");
    expect_contains("CID extension rejects rehandshake CID changes", cid_parse,
                    "For now we don't support changing the CID on a rehandshake");
    expect_contains("CID API rejects changing CID during connection", cid_set,
                    "wolfSSL doesn't support changing the CID during a ");

    printf("\nConclusion: %s\n", failures == 0
        ? "PASS - source behavior confirms IDs 185/186/187 are unsatisfied: wolfSSL supports static DTLS CID negotiation/header parsing, but it has no RequestConnectionId/NewConnectionId message types, no cid_spare/cid_immediate usage semantics, and no response state machine."
        : "FAIL - one or more source assertions did not match the audited tree.");

    free(cid_info);
    free(handshake_enum);
    free(dispatcher);
    free(cid_parse);
    free(cid_set);
    free(dtls13_cid);
    free(internal);
    free(dtls);
    free(dtls13);
    free(tls13);
    free(tests);
    return failures == 0 ? 0 : 1;
}
