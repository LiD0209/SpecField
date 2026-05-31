/*
 * Compiled source-check harness for RFC 9147 dynamic Connection ID update
 * messages in wolfSSL.
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

static int check(const char *name, int condition)
{
    printf("%s %s\n", condition ? "PASS" : "FAIL", name);
    return condition;
}

int main(void)
{
    const char *root = "D:\\project\\wolfssl-master\\";
    char path[512];
    char *internal;
    char *tls13;
    char *dtls;
    char *dtls13;
    int ok = 1;

    snprintf(path, sizeof(path), "%swolfssl\\internal.h", root);
    internal = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\tls13.c", root);
    tls13 = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\dtls.c", root);
    dtls = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\dtls13.c", root);
    dtls13 = read_file(path);

    if (internal == NULL || tls13 == NULL || dtls == NULL || dtls13 == NULL) {
        free(internal);
        free(tls13);
        free(dtls);
        free(dtls13);
        return 2;
    }

    ok &= check("CIDInfo stores only current tx/rx CID pointers",
        has(internal, "ConnectionID* tx;") &&
        has(internal, "ConnectionID* rx;") &&
        has(internal, "byte negotiated : 1;"));
    ok &= check("Handshake enum lacks request_connection_id",
        !has(internal, "request_connection_id"));
    ok &= check("Handshake enum lacks new_connection_id",
        !has(internal, "new_connection_id"));
    ok &= check("No RequestConnectionId implementation in checked protocol files",
        !has(internal, "RequestConnectionId") &&
        !has(tls13, "RequestConnectionId") &&
        !has(dtls, "RequestConnectionId") &&
        !has(dtls13, "RequestConnectionId"));
    ok &= check("No NewConnectionId implementation in checked protocol files",
        !has(internal, "NewConnectionId") &&
        !has(tls13, "NewConnectionId") &&
        !has(dtls, "NewConnectionId") &&
        !has(dtls13, "NewConnectionId"));
    ok &= check("No ConnectionIdUsage/cid_immediate/cid_spare symbols",
        !has(internal, "ConnectionIdUsage") &&
        !has(tls13, "ConnectionIdUsage") &&
        !has(dtls, "ConnectionIdUsage") &&
        !has(dtls13, "ConnectionIdUsage") &&
        !has(internal, "cid_immediate") &&
        !has(tls13, "cid_immediate") &&
        !has(dtls, "cid_immediate") &&
        !has(dtls13, "cid_immediate") &&
        !has(internal, "cid_spare") &&
        !has(tls13, "cid_spare") &&
        !has(dtls, "cid_spare") &&
        !has(dtls13, "cid_spare"));
    ok &= check("Existing API rejects changing CID during a connection",
        has(dtls, "doesn't support changing the CID during a"));
    ok &= check("DTLS extension parser rejects changing CID on rehandshake",
        has(dtls, "don't support changing the CID on a rehandshake"));
    ok &= check("Static DTLS 1.3 CID record support exists",
        has(dtls13, "Dtls13AddCID") &&
        has(dtls13, "Dtls13UnifiedHeaderParseCID") &&
        has(dtls13, "wolfSSL_dtls_cid_get_tx") &&
        has(dtls13, "DtlsCIDCheck"));

    free(internal);
    free(tls13);
    free(dtls);
    free(dtls13);

    if (ok) {
        printf("RESULT confirmed: static CID support exists, dynamic RFC9147 CID update messages and queues are absent\n");
    }
    else {
        printf("RESULT failed\n");
    }
    return ok ? 0 : 1;
}
