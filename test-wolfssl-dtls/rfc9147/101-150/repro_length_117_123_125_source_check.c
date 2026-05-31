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
        printf("PASS %-62s contains \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-62s missing \"%s\"\n", name, needle);
        failures++;
    }
}

static void expect_absent(const char *name, const char *text, const char *needle) {
    if (text != NULL && strstr(text, needle) == NULL) {
        printf("PASS %-62s does not contain \"%s\"\n", name, needle);
    } else {
        printf("FAIL %-62s unexpectedly contains \"%s\"\n", name, needle);
        failures++;
    }
}

int main(void) {
    char *dtls13 = read_file("D:\\project\\wolfssl-master\\src\\dtls13.c");
    char *internal_c = read_file("D:\\project\\wolfssl-master\\src\\internal.c");
    char *internal_h = read_file("D:\\project\\wolfssl-master\\wolfssl\\internal.h");
    char *tests = read_file("D:\\project\\wolfssl-master\\tests\\api\\test_dtls.c");
    char *add_hdr;
    char *parse_hdr;
    char *get_dtls13_header;
    char *get_record_header;
    char *max_plain;

    if (dtls13 == NULL || internal_c == NULL || internal_h == NULL || tests == NULL) {
        return 2;
    }

    add_hdr = slice_between(dtls13, "int Dtls13RlAddCiphertextHeader(",
                            "int Dtls13HandshakeAddHeader");
    parse_hdr = slice_between(dtls13, "int Dtls13ParseUnifiedRecordLayer(",
                              "int Dtls13RecordRecvd");
    get_dtls13_header = slice_between(internal_c, "static int GetDtls13RecordHeader(",
                                      "static int GetDtlsRecordHeader(");
    get_record_header = slice_between(internal_c, "static int GetRecordHeader(",
                                      "static int GetInputData(");
    max_plain = slice_between(internal_c, "int wolfssl_local_GetMaxPlaintextSize(",
                              "/**\n * Return the max fragment size.");

    printf("== ID 123: L bit and omitted length behavior ==\n");
    expect_contains("sender includes DTLS 1.3 length bit", add_hdr,
                    "*flags |= DTLS13_LEN_BIT;");
    expect_contains("sender writes explicit record length", add_hdr,
                    "c16toa(length, out + idx);");
    expect_contains("parser detects L bit", parse_hdr,
                    "hasLength = flags & DTLS13_LEN_BIT;");
    expect_contains("parser treats omitted length as datagram remainder", parse_hdr,
                    "hdrInfo->recordLength = inputSize - idx;");
    expect_absent("no sender-side omitted-length branch in header writer", add_hdr,
                  "*flags &= ~DTLS13_LEN_BIT");

    printf("\n== ID 125: explicit length datagram bounds ==\n");
    expect_contains("parser reads explicit 16-bit length", parse_hdr,
                    "ato16(input + idx, &hdrInfo->recordLength);");
    expect_contains("parser checks length field bytes are present", parse_hdr,
                    "if (inputSize < idx + DTLS13_LEN_SIZE)");
    expect_contains("parser checks minimum ciphertext bytes for RN mask", parse_hdr,
                    "if (inputSize < idx + DTLS13_RN_MASK_SIZE)");
    expect_absent("parser has no direct full-record bound check", parse_hdr,
                  "idx + hdrInfo->recordLength");
    expect_contains("higher layer rejects partial UDP record", get_dtls13_header,
                    "DTLS_PARTIAL_RECORD_READ");
    expect_contains("wolfSSL test mutates length larger than datagram", tests,
                    "test_dtls13_longer_length");

    printf("\n== ID 117: 2^14 maximum record-size policy ==\n");
    expect_contains("2^14 maximum record constant exists", internal_h,
                    "#define MAX_RECORD_SIZE 16384");
    expect_contains("maximum plaintext size starts from configured max fragment", max_plain,
                    "maxFrag = wolfSSL_GetMaxFragSize(ssl);");
    expect_contains("receive path applies max record size plus overhead", get_record_header,
                    "MAX_RECORD_SIZE + MAX_MSG_EXTRA");
    expect_absent("no explicit DTLS-over-TCP mode symbol", internal_c,
                  "DTLS_OVER_TCP");
    expect_absent("no explicit DTLS-over-TCP mode symbol in headers", internal_h,
                  "DTLS_OVER_TCP");

    printf("\nConclusion: %s\n", failures == 0
        ? "PASS - source behavior confirms partial findings: wolfSSL always sends DTLS 1.3 records with L bit set and has generic 2^14 record sizing plus tests for oversized explicit length, but the parser lacks a direct idx+recordLength<=inputSize check and no DTLS-over-TCP-specific 2^14 branch was found."
        : "FAIL - one or more source assertions did not match the audited tree.");

    free(add_hdr);
    free(parse_hdr);
    free(get_dtls13_header);
    free(get_record_header);
    free(max_plain);
    free(dtls13);
    free(internal_c);
    free(internal_h);
    free(tests);
    return failures == 0 ? 0 : 1;
}
