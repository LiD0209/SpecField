/*
 * Compiled source-check harness for RFC 9147 DTLS 1.3 close_notify
 * epoch/sequence boundary handling in wolfSSL.
 *
 * The target behavior is structural: after receiving a valid closure alert, a
 * DTLS 1.3 implementation needs the alert record's epoch/sequence pair in
 * order to ignore later data by record number. This harness verifies the
 * implemented close_notify path and checks for the missing stored boundary.
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

static int has_any_boundary_name(const char *source)
{
    return has(source, "closeNotifyEpoch") ||
           has(source, "closeNotifySeq") ||
           has(source, "closureEpoch") ||
           has(source, "closureSeq") ||
           has(source, "close_notify_epoch") ||
           has(source, "close_notify_seq") ||
           has(source, "closure_alert_epoch") ||
           has(source, "closure_alert_seq");
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
    char *internal_h;
    char *internal_c;
    int ok = 1;

    snprintf(path, sizeof(path), "%swolfssl\\internal.h", root);
    internal_h = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\internal.c", root);
    internal_c = read_file(path);

    if (internal_h == NULL || internal_c == NULL) {
        free(internal_h);
        free(internal_c);
        return 2;
    }

    ok &= check("closeNotify state bit exists",
        has(internal_h, "closeNotify:1") &&
        has(internal_h, "we've received a close notify"));
    ok &= check("DTLS current record epoch/sequence fields exist",
        has(internal_h, "curEpoch64") &&
        has(internal_h, "curSeq;") &&
        has(internal_h, "Received epoch in current record") &&
        has(internal_h, "Received sequence in current record"));
    ok &= check("DoAlert sets closeNotify on close_notify",
        has(internal_c, "if (*type == close_notify)") &&
        has(internal_c, "ssl->options.closeNotify = 1"));
    ok &= check("record alert dispatch returns ZERO_RETURN on close_notify",
        has(internal_c, "if (type == close_notify)") &&
        has(internal_c, "ssl->options.processReply = doProcessInit") &&
        has(internal_c, "return ssl->error = ZERO_RETURN"));
    ok &= check("no stored closure alert epoch/sequence boundary fields",
        !has_any_boundary_name(internal_h) &&
        !has_any_boundary_name(internal_c));
    ok &= check("no RFC closure-boundary wording in receive implementation",
        !has(internal_c, "valid received closure alert") &&
        !has(internal_c, "epoch/sequence number pair after"));

    free(internal_h);
    free(internal_c);

    if (ok) {
        printf("RESULT confirmed: close_notify is handled as shutdown state, but no stored closure epoch/sequence boundary was found\n");
    }
    else {
        printf("RESULT failed\n");
    }
    return ok ? 0 : 1;
}
