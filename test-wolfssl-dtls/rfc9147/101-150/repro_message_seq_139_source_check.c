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
    char *dtls13 = read_file("D:\\project\\wolfssl-master\\src\\dtls13.c");
    char *tls13 = read_file("D:\\project\\wolfssl-master\\src\\tls13.c");
    char *internal = read_file("D:\\project\\wolfssl-master\\src\\internal.c");
    char *tests = read_file("D:\\project\\wolfssl-master\\tests\\api\\test_dtls.c");
    char *add_header;
    char *hs_send;
    char *key_update;
    char *new_ticket;
    char *send_finished;
    char *do_finished;

    if (dtls13 == NULL || tls13 == NULL || internal == NULL || tests == NULL) {
        return 2;
    }

    add_header = slice_between(dtls13, "int Dtls13HandshakeAddHeader(",
                               "int Dtls13MinimumRecordLength(");
    hs_send = slice_between(dtls13, "int Dtls13HandshakeSend(",
                            "#define SN_LABEL_SZ");
    key_update = slice_between(tls13, "int SendTls13KeyUpdate(",
                               "/* handle processing TLS v1.3 key_update");
    new_ticket = slice_between(tls13, "static int SendTls13NewSessionTicket(",
                               "#ifndef NO_WOLFSSL_CLIENT");
    send_finished = slice_between(internal, "int SendFinished(",
                                  "#endif /* WOLFSSL_NO_TLS12 */");
    do_finished = slice_between(internal, "int DoFinished(",
                                "/* Make sure no duplicates");

    printf("== DTLS 1.3 message_seq source ==\n");
    expect_contains("DTLS 1.3 handshake header uses dtls_handshake_number",
                    add_header, "c16toa(ssl->keys.dtls_handshake_number, hdr->messageSeq);");
    expect_contains("new sends increment dtls_handshake_number",
                    hs_send, "ssl->keys.dtls_handshake_number++;");
    expect_contains("retransmission path can reuse buffered record message_seq",
                    dtls13, "rtxRecords");

    printf("\n== Post-handshake messages use the same sender ==\n");
    expect_contains("KeyUpdate sends through Dtls13HandshakeSend",
                    key_update, "Dtls13HandshakeSend(ssl, output");
    expect_contains("KeyUpdate identifies handshake type key_update",
                    key_update, "key_update, 0");
    expect_contains("NewSessionTicket sends through Dtls13HandshakeSend",
                    new_ticket, "Dtls13HandshakeSend(ssl, output");
    expect_contains("NewSessionTicket identifies handshake type session_ticket",
                    new_ticket, "session_ticket, 0");

    printf("\n== Reset paths after Finished ==\n");
    expect_contains("SendFinished resets DTLS handshake number",
                    send_finished, "ssl->keys.dtls_handshake_number = 0;");
    expect_contains("SendFinished reset is under generic WOLFSSL_DTLS",
                    send_finished, "#ifdef WOLFSSL_DTLS");
    expect_absent("SendFinished reset is not guarded away for DTLS 1.3",
                  send_finished, "!IsAtLeastTLSv1_3");
    expect_contains("DoFinished resets DTLS handshake number",
                    do_finished, "ssl->keys.dtls_handshake_number = 0;");
    expect_contains("DoFinished reset is under generic WOLFSSL_DTLS",
                    do_finished, "#ifdef WOLFSSL_DTLS");
    expect_absent("DoFinished reset is not guarded away for DTLS 1.3",
                  do_finished, "!IsAtLeastTLSv1_3");

    printf("\n== Test coverage ==\n");
    expect_contains("tests have helper to read message_seq",
                    tests, "test_dtls13_get_message_seq");
    expect_contains("tests cover CH retransmission message_seq",
                    tests, "message_seq remains the original CH1 value");
    expect_absent("no direct post-handshake message_seq continuity test",
                  tests, "post-handshake message_seq");
    expect_absent("no NewSessionTicket message_seq assertion",
                  tests, "NewSessionTicket message_seq");
    expect_absent("no KeyUpdate message_seq assertion",
                  tests, "KeyUpdate message_seq");

    printf("\nConclusion: %s\n", failures == 0
        ? "PASS - source behavior confirms ID 139 as a real partial/likely mismatch: DTLS 1.3 post-handshake messages use dtls_handshake_number, but generic DTLS Finished paths reset that counter to zero and no direct post-handshake message_seq continuity test was found."
        : "FAIL - one or more source assertions did not match the audited tree.");

    free(add_header);
    free(hs_send);
    free(key_update);
    free(new_ticket);
    free(send_finished);
    free(do_finished);
    free(dtls13);
    free(tls13);
    free(internal);
    free(tests);
    return failures == 0 ? 0 : 1;
}
