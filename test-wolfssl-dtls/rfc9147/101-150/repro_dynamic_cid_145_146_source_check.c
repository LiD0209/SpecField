/*
 * Compiled source-check harness for RFC 9147 DTLS 1.3 dynamic Connection ID
 * request/response messages in wolfSSL.
 *
 * IDs 145 and 146 concern RequestConnectionId.num_cids and the required
 * NewConnectionId response with usage cid_spare. The implementation can support
 * negotiated/static CIDs, but needs post-handshake message definitions and
 * state-machine paths to satisfy these requirements.
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
    char *test_dtls;
    int ok = 1;

    snprintf(path, sizeof(path), "%swolfssl\\internal.h", root);
    internal = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\tls13.c", root);
    tls13 = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\dtls.c", root);
    dtls = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\dtls13.c", root);
    dtls13 = read_file(path);
    snprintf(path, sizeof(path), "%stests\\api\\test_dtls.c", root);
    test_dtls = read_file(path);

    if (internal == NULL || tls13 == NULL || dtls == NULL ||
            dtls13 == NULL || test_dtls == NULL) {
        free(internal);
        free(tls13);
        free(dtls);
        free(dtls13);
        free(test_dtls);
        return 2;
    }

    ok &= check("Static CID state stores only current tx/rx pointers",
        has(internal, "ConnectionID* tx;") &&
        has(internal, "ConnectionID* rx;") &&
        has(internal, "byte negotiated : 1;"));
    ok &= check("Static DTLS CID extension parser exists",
        has(dtls, "TLSX_ConnectionID_Parse") &&
        has(dtls, "wolfSSL_dtls_cid_use") &&
        has(dtls, "wolfSSL_dtls_cid_set"));
    ok &= check("DTLS 1.3 unified header CID support exists",
        has(dtls13, "Dtls13AddCID") &&
        has(dtls13, "Dtls13UnifiedHeaderParseCID") &&
        has(dtls13, "DTLS13_CID_BIT") &&
        has(dtls13, "DtlsCIDCheck"));
    ok &= check("Built-in tests cover static DTLS 1.3 CID behavior",
        has(test_dtls, "test_dtls13_basic_connection_id") &&
        has(test_dtls, "ExpectNotNull(CLIENT_CID())") &&
        has(test_dtls, "ExpectNotNull(SERVER_CID())"));
    ok &= check("Handshake enum lacks request_connection_id(9)",
        !has(internal, "request_connection_id"));
    ok &= check("Handshake enum lacks new_connection_id(10)",
        !has(internal, "new_connection_id"));
    ok &= check("TLS 1.3 dispatcher has no dynamic CID message cases",
        !has(tls13, "case request_connection_id") &&
        !has(tls13, "case new_connection_id") &&
        !has(tls13, "RequestConnectionId") &&
        !has(tls13, "NewConnectionId"));
    ok &= check("Protocol source lacks RequestConnectionId/NewConnectionId implementations",
        !has(internal, "RequestConnectionId") &&
        !has(dtls, "RequestConnectionId") &&
        !has(dtls13, "RequestConnectionId") &&
        !has(internal, "NewConnectionId") &&
        !has(dtls, "NewConnectionId") &&
        !has(dtls13, "NewConnectionId"));
    ok &= check("Protocol source lacks num_cids and cid_spare handling",
        !has(internal, "num_cids") &&
        !has(tls13, "num_cids") &&
        !has(dtls, "num_cids") &&
        !has(dtls13, "num_cids") &&
        !has(internal, "cid_spare") &&
        !has(tls13, "cid_spare") &&
        !has(dtls, "cid_spare") &&
        !has(dtls13, "cid_spare"));
    ok &= check("Protocol source lacks ConnectionIdUsage/cid_immediate handling",
        !has(internal, "ConnectionIdUsage") &&
        !has(tls13, "ConnectionIdUsage") &&
        !has(dtls, "ConnectionIdUsage") &&
        !has(dtls13, "ConnectionIdUsage") &&
        !has(internal, "cid_immediate") &&
        !has(tls13, "cid_immediate") &&
        !has(dtls, "cid_immediate") &&
        !has(dtls13, "cid_immediate"));
    ok &= check("Existing API rejects changing CID during a connection",
        has(dtls, "doesn't support changing the CID during a"));
    ok &= check("Extension parser rejects changing CID on rehandshake",
        has(dtls, "don't support changing the CID on a rehandshake"));

    free(internal);
    free(tls13);
    free(dtls);
    free(dtls13);
    free(test_dtls);

    if (ok) {
        printf("RESULT confirmed: wolfSSL has static CID support, but no RFC9147 RequestConnectionId/NewConnectionId num_cids/cid_spare state machine\n");
    }
    else {
        printf("RESULT failed\n");
    }
    return ok ? 0 : 1;
}
