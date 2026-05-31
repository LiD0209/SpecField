/*
 * Compiled source-check harness for RFC 9147 DTLS 1.3 PMTU-unknown
 * retransmission backoff behavior in wolfSSL.
 *
 * RFC 9147 recommends that repeated retransmissions with unknown PMTU back
 * off to smaller records and re-fragment handshake messages. This harness
 * checks the implemented initial fragmentation path and the retransmission
 * path, then verifies that the retransmission path does not contain a PMTU
 * backoff/re-fragmentation decision point.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    long size;
    char *buf;

    if (fp == NULL) {
        printf("FAIL open %s\n", path);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    size = ftell(fp);
    if (size < 0) {
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }
    buf = (char *)malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(fp);
        return NULL;
    }
    if (fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return NULL;
    }
    buf[size] = '\0';
    fclose(fp);
    return buf;
}

static int has(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static int section_has(const char *source, const char *start,
    const char *end, const char *needle)
{
    const char *s = strstr(source, start);
    const char *e;
    size_t n;

    if (s == NULL) {
        return 0;
    }
    e = strstr(s, end);
    if (e == NULL || e <= s) {
        e = source + strlen(source);
    }
    n = (size_t)(e - s);
    return n >= strlen(needle) && strstr(s, needle) != NULL &&
        (size_t)(strstr(s, needle) - s) < n;
}

static int section_lacks_backoff_terms(const char *source, const char *start,
    const char *end)
{
    const char *terms[] = {
        "pmtu", "PMTU", "mtu", "Mtu", "backoff", "back off",
        "smaller", "shrink", "reduce", "maxFrag",
        "GetMaxPlaintextSize", "GetRecordSize", "refragment",
        "re-fragment", "triggeredRtxs"
    };
    const char *s = strstr(source, start);
    const char *e;
    size_t n;
    size_t i;

    if (s == NULL) {
        return 0;
    }
    e = strstr(s, end);
    if (e == NULL || e <= s) {
        e = source + strlen(source);
    }
    n = (size_t)(e - s);

    for (i = 0; i < sizeof(terms) / sizeof(terms[0]); i++) {
        const char *p = strstr(s, terms[i]);
        if (p != NULL && (size_t)(p - s) < n) {
            return 0;
        }
    }
    return 1;
}

static int check(const char *name, int condition)
{
    printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    return condition;
}

int main(void)
{
    const char *root = "D:\\project\\wolfssl-master\\";
    char path[512];
    char *dtls13;
    char *internal_c;
    char *internal_h;
    int ok = 1;

    snprintf(path, sizeof(path), "%ssrc\\dtls13.c", root);
    dtls13 = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\internal.c", root);
    internal_c = read_file(path);
    snprintf(path, sizeof(path), "%swolfssl\\internal.h", root);
    internal_h = read_file(path);

    if (dtls13 == NULL || internal_c == NULL || internal_h == NULL) {
        free(dtls13);
        free(internal_c);
        free(internal_h);
        return 2;
    }

    ok &= check("initial DTLS 1.3 handshake fragmentation uses max plaintext size",
        section_has(dtls13, "int Dtls13HandshakeSend", "#define SN_LABEL_SZ",
            "wolfssl_local_GetMaxPlaintextSize") &&
        section_has(dtls13, "int Dtls13HandshakeSend", "#define SN_LABEL_SZ",
            "Dtls13SendFragmented"));
    ok &= check("fragmented send path recalculates fragment length from current MTU sizing",
        section_has(dtls13, "static int Dtls13SendFragmentedInternal",
            "static int Dtls13SendFragmented", "maxFragment") &&
        section_has(dtls13, "static int Dtls13SendFragmentedInternal",
            "static int Dtls13SendFragmented", "wolfssl_local_GetRecordSize"));
    ok &= check("retransmission timeout resends buffered records",
        section_has(dtls13, "int Dtls13RtxTimeout",
            "static int Dtls13RtxHasKeyUpdateBuffered",
            "Dtls13RtxSendBuffered"));
    ok &= check("buffered retransmission reuses stored record length",
        section_has(dtls13, "static int Dtls13RtxSendBuffered",
            "static int Dtls13AcceptFragmented", "sendSz = r->length + headerLength") &&
        section_has(dtls13, "static int Dtls13RtxSendBuffered",
            "static int Dtls13AcceptFragmented", "XMEMCPY(output + headerLength, r->data, r->length)") &&
        section_has(dtls13, "static int Dtls13RtxSendBuffered",
            "static int Dtls13AcceptFragmented", "Dtls13SendFragment"));
    ok &= check("retransmission timeout has no PMTU backoff or size-shrink branch",
        section_lacks_backoff_terms(dtls13, "int Dtls13RtxTimeout",
            "static int Dtls13RtxHasKeyUpdateBuffered"));
    ok &= check("buffered retransmission has no re-fragment-to-smaller-record branch",
        section_lacks_backoff_terms(dtls13, "static int Dtls13RtxSendBuffered",
            "static int Dtls13AcceptFragmented"));
    ok &= check("normal MTU controls exist outside retransmission backoff path",
        has(internal_h, "dtlsMtuSz") &&
        has(internal_c, "wolfssl_local_GetMaxPlaintextSize") &&
        has(internal_c, "wolfssl_local_GetRecordSize"));
    ok &= check("retransmission counter is not used for PMTU backoff",
        has(internal_h, "byte triggeredRtxs; /* Unused? */") &&
        !has(dtls13, "triggeredRtxs++") &&
        !has(dtls13, "triggeredRtxs ="));

    free(dtls13);
    free(internal_c);
    free(internal_h);

    if (ok) {
        printf("RESULT confirmed: wolfSSL fragments initial DTLS 1.3 sends, but repeated retransmission does not back off to smaller records when PMTU is unknown\n");
    }
    else {
        printf("RESULT failed\n");
    }
    return ok ? 0 : 1;
}
