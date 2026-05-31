/*
 * Focused runtime harness for RFC 9147 DTLS 1.3 sending epoch limit.
 *
 * This intentionally exercises the same w64-style epoch arithmetic and
 * wrap-to-zero predicate used by wolfSSL's DTLS KeyUpdate epoch path. It avoids
 * a full DTLS session because reaching 2^48 KeyUpdates over the network is not
 * practical for a regression harness.
 */
#include <stdint.h>
#include <stdio.h>

typedef struct {
    uint32_t hi;
    uint32_t lo;
} w64pair;

static void w64_increment(w64pair *n)
{
    n->lo++;
    if (n->lo == 0) {
        n->hi++;
    }
}

static int w64_is_zero(w64pair n)
{
    return n.hi == 0 && n.lo == 0;
}

static int wolfssl_current_epoch_gate_allows_next(w64pair epoch)
{
    w64_increment(&epoch);

    /* Mirrors wolfSSL src/dtls13.c: Dtls13KeyUpdateAckReceived. */
    if (w64_is_zero(epoch)) {
        return 0;
    }

    return 1;
}

static int rfc9147_sender_epoch_gate_allows_next(w64pair epoch)
{
    const w64pair max_sender_epoch = {0x0000ffffu, 0xffffffffu};

    if (epoch.hi > max_sender_epoch.hi) {
        return 0;
    }
    if (epoch.hi == max_sender_epoch.hi &&
            epoch.lo >= max_sender_epoch.lo) {
        return 0;
    }
    return 1;
}

static int expect_equal(const char *name, int got, int want)
{
    if (got != want) {
        printf("FAIL %s: got=%d want=%d\n", name, got, want);
        return 0;
    }

    printf("PASS %s: got=%d\n", name, got);
    return 1;
}

int main(void)
{
    int ok = 1;
    w64pair epoch_traffic = {0x00000000u, 0x00000003u};
    w64pair epoch_2p48_minus_2 = {0x0000ffffu, 0xfffffffeu};
    w64pair epoch_2p48_minus_1 = {0x0000ffffu, 0xffffffffu};
    w64pair epoch_2p64_minus_1 = {0xffffffffu, 0xffffffffu};
    w64pair incremented = epoch_2p48_minus_1;

    w64_increment(&incremented);
    printf("INFO increment 2^48-1 -> hi=0x%08x lo=0x%08x zero=%d\n",
        incremented.hi, incremented.lo, w64_is_zero(incremented));

    ok &= expect_equal("normal epoch allowed by current wolfSSL gate",
        wolfssl_current_epoch_gate_allows_next(epoch_traffic), 1);
    ok &= expect_equal("2^48-2 allowed by RFC sender gate",
        rfc9147_sender_epoch_gate_allows_next(epoch_2p48_minus_2), 1);
    ok &= expect_equal("2^48-2 allowed by current wolfSSL gate",
        wolfssl_current_epoch_gate_allows_next(epoch_2p48_minus_2), 1);
    ok &= expect_equal("2^48-1 rejected by RFC sender gate",
        rfc9147_sender_epoch_gate_allows_next(epoch_2p48_minus_1), 0);
    ok &= expect_equal("2^48-1 still allowed by current wolfSSL gate",
        wolfssl_current_epoch_gate_allows_next(epoch_2p48_minus_1), 1);
    ok &= expect_equal("2^64-1 rejected by current wolfSSL wrap gate",
        wolfssl_current_epoch_gate_allows_next(epoch_2p64_minus_1), 0);

    if (!ok) {
        printf("RESULT failed\n");
        return 1;
    }

    printf("RESULT confirmed: wrap-to-zero gate permits epoch 2^48, while RFC 9147 sender gate would stop at 2^48-1\n");
    return 0;
}
