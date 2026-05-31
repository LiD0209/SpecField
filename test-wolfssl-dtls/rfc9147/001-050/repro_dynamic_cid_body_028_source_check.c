/*
 * Compiled source-check harness for RFC 9147 DTLSHandshake.body dynamic CID
 * alternatives in wolfSSL.
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
    char *dtls13;
    int ok = 1;

    snprintf(path, sizeof(path), "%swolfssl\\internal.h", root);
    internal = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\tls13.c", root);
    tls13 = read_file(path);
    snprintf(path, sizeof(path), "%ssrc\\dtls13.c", root);
    dtls13 = read_file(path);

    if (internal == NULL || tls13 == NULL || dtls13 == NULL) {
        free(internal);
        free(tls13);
        free(dtls13);
        return 2;
    }

    ok &= check("HandshakeType enum has ordinary TLS 1.3 body types",
        has(internal, "enum HandShakeType") &&
        has(internal, "client_hello") &&
        has(internal, "server_hello") &&
        has(internal, "certificate_request") &&
        has(internal, "finished") &&
        has(internal, "key_update"));
    ok &= check("HandshakeType enum lacks request_connection_id",
        !has(internal, "request_connection_id"));
    ok &= check("HandshakeType enum lacks new_connection_id",
        !has(internal, "new_connection_id"));
    ok &= check("DTLS handshake receive path forwards body to TLS13 dispatcher",
        has(dtls13, "GetDtlsHandShakeHeader") &&
        has(dtls13, "DoTls13HandShakeMsgType"));
    ok &= check("TLS13 dispatcher handles ordinary body cases",
        has(tls13, "case server_hello:") &&
        has(tls13, "case certificate_request:") &&
        has(tls13, "case key_update:"));
    ok &= check("TLS13 dispatcher has no request_connection_id branch",
        !has(tls13, "case request_connection_id") &&
        !has(tls13, "RequestConnectionId"));
    ok &= check("TLS13 dispatcher has no new_connection_id branch",
        !has(tls13, "case new_connection_id") &&
        !has(tls13, "NewConnectionId"));
    ok &= check("Static DTLS CID record support exists",
        has(dtls13, "Dtls13AddCID") &&
        has(dtls13, "Dtls13UnifiedHeaderParseCID") &&
        has(internal, "ConnectionID* tx;") &&
        has(internal, "ConnectionID* rx;"));

    free(internal);
    free(tls13);
    free(dtls13);

    if (ok) {
        printf("RESULT confirmed: ordinary DTLSHandshake body handling exists, dynamic CID body branches are absent\n");
    }
    else {
        printf("RESULT failed\n");
    }
    return ok ? 0 : 1;
}
