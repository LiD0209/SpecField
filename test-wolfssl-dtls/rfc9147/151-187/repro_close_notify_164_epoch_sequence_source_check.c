#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    char *buf;
    long len;

    if (f == NULL) {
        fprintf(stderr, "FAIL cannot open %s\n", path);
        exit(2);
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "FAIL cannot seek %s\n", path);
        exit(2);
    }
    len = ftell(f);
    if (len < 0) {
        fprintf(stderr, "FAIL cannot tell %s\n", path);
        exit(2);
    }
    rewind(f);
    buf = (char *)malloc((size_t)len + 1);
    if (buf == NULL) {
        fprintf(stderr, "FAIL malloc\n");
        exit(2);
    }
    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        fprintf(stderr, "FAIL cannot read %s\n", path);
        exit(2);
    }
    fclose(f);
    buf[len] = '\0';
    if (out_len != NULL) {
        *out_len = len;
    }
    return buf;
}

static int contains(const char *haystack, const char *needle) {
    return strstr(haystack, needle) != NULL;
}

static void require_present(const char *label, const char *haystack,
                            const char *needle, int *failures) {
    if (contains(haystack, needle)) {
        printf("PASS present: %s\n", label);
    } else {
        printf("FAIL missing: %s\n", label);
        (*failures)++;
    }
}

static void require_absent(const char *label, const char *haystack,
                           const char *needle, int *failures) {
    if (!contains(haystack, needle)) {
        printf("PASS absent: %s\n", label);
    } else {
        printf("FAIL unexpected presence: %s\n", label);
        (*failures)++;
    }
}

int main(void) {
    const char *root = "D:/project/wolfssl-master/";
    const char *internal_c_path = "D:/project/wolfssl-master/src/internal.c";
    const char *internal_h_path = "D:/project/wolfssl-master/wolfssl/internal.h";
    char *internal_c;
    char *internal_h;
    int failures = 0;

    (void)root;
    internal_c = read_file(internal_c_path, NULL);
    internal_h = read_file(internal_h_path, NULL);

    require_present("DTLS 1.3 current record epoch is reconstructed",
        internal_c, "ssl->keys.curEpoch64 = epochNumber;", &failures);
    require_present("DTLS 1.3 current record sequence is reconstructed",
        internal_c, "Dtls13ReconstructSeqNumber(ssl, &hdrInfo, &ssl->keys.curSeq)",
        &failures);
    require_present("current DTLS 1.3 record epoch field exists",
        internal_h, "w64wrapper curEpoch64;", &failures);
    require_present("current DTLS 1.3 record sequence field exists",
        internal_h, "w64wrapper curSeq;", &failures);
    require_present("close_notify boolean state exists",
        internal_h, "closeNotify:1", &failures);
    require_present("DoAlert marks close_notify as received",
        internal_c, "ssl->options.closeNotify = 1;", &failures);
    require_present("close_notify dispatch returns ZERO_RETURN",
        internal_c, "return ssl->error = ZERO_RETURN;", &failures);

    require_absent("stored closeNotifyEpoch boundary field",
        internal_h, "closeNotifyEpoch", &failures);
    require_absent("stored closeNotifySeq boundary field",
        internal_h, "closeNotifySeq", &failures);
    require_absent("stored close_notify_epoch boundary field",
        internal_h, "close_notify_epoch", &failures);
    require_absent("stored close_notify_seq boundary field",
        internal_h, "close_notify_seq", &failures);
    require_absent("stored closureEpoch boundary field",
        internal_h, "closureEpoch", &failures);
    require_absent("stored closureSeq boundary field",
        internal_h, "closureSeq", &failures);

    if (failures == 0) {
        printf("RESULT confirmed partial: close_notify shutdown is implemented, "
               "but no stored epoch/sequence boundary for RFC 9147 post-close "
               "ignore logic was found.\n");
    } else {
        printf("RESULT inconclusive: %d source checks failed.\n", failures);
    }

    free(internal_c);
    free(internal_h);
    return failures == 0 ? 0 : 1;
}
