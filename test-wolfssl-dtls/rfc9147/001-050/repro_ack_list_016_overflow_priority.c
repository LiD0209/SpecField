/*
 * Focused runtime harness for wolfSSL DTLS 1.3 ACK-list capacity behavior.
 *
 * This mirrors the relevant Dtls13RtxAddAck model: a bounded sorted list of
 * epoch/sequence pairs with duplicate suppression. The node has no field for
 * "already acknowledged", so when the list is full a newly received record is
 * silently dropped instead of replacing a record that was already covered by a
 * prior ACK.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define ACK_MAX_RECORDS 8

typedef struct AckNode {
    uint64_t epoch;
    uint64_t seq;
    struct AckNode *next;
} AckNode;

typedef struct AckList {
    AckNode *head;
    unsigned count;
} AckList;

static int pair_less(uint64_t epoch_a, uint64_t seq_a,
    uint64_t epoch_b, uint64_t seq_b)
{
    return epoch_a < epoch_b || (epoch_a == epoch_b && seq_a < seq_b);
}

static int add_ack(AckList *list, uint64_t epoch, uint64_t seq)
{
    AckNode **prev_next = &list->head;
    AckNode *cur = list->head;
    unsigned count = 0;
    AckNode *node;

    if (list->count >= ACK_MAX_RECORDS) {
        return 0; /* list full, silently drop */
    }

    while (cur != NULL) {
        count++;
        if (cur->epoch == epoch && cur->seq == seq) {
            return 0; /* duplicate */
        }
        if (pair_less(epoch, seq, cur->epoch, cur->seq)) {
            break;
        }
        prev_next = &cur->next;
        cur = cur->next;
    }

    if (count >= ACK_MAX_RECORDS) {
        return 0; /* insertion position past bounded capacity */
    }

    node = (AckNode *)calloc(1, sizeof(*node));
    if (node == NULL) {
        return -1;
    }
    node->epoch = epoch;
    node->seq = seq;
    node->next = cur;
    *prev_next = node;
    list->count++;
    return 0;
}

static void free_list(AckList *list)
{
    AckNode *cur = list->head;
    while (cur != NULL) {
        AckNode *next = cur->next;
        free(cur);
        cur = next;
    }
    list->head = NULL;
    list->count = 0;
}

static int contains(AckList *list, uint64_t epoch, uint64_t seq)
{
    AckNode *cur = list->head;
    while (cur != NULL) {
        if (cur->epoch == epoch && cur->seq == seq) {
            return 1;
        }
        cur = cur->next;
    }
    return 0;
}

static int expect_equal(const char *name, uint64_t got, uint64_t want)
{
    if (got != want) {
        printf("FAIL %s: got=%llu want=%llu\n", name,
            (unsigned long long)got, (unsigned long long)want);
        return 0;
    }
    printf("PASS %s: got=%llu\n", name, (unsigned long long)got);
    return 1;
}

int main(void)
{
    AckList list = {0};
    int ok = 1;
    unsigned i;

    for (i = 0; i < ACK_MAX_RECORDS; i++) {
        ok &= expect_equal("fill add returns success", add_ack(&list, 0, i), 0);
    }
    ok &= expect_equal("list reaches capacity", list.count, ACK_MAX_RECORDS);

    ok &= expect_equal("duplicate at capacity returns success", add_ack(&list, 0, 3), 0);
    ok &= expect_equal("duplicate does not grow list", list.count, ACK_MAX_RECORDS);

    ok &= expect_equal("new record at capacity returns success", add_ack(&list, 0, 999), 0);
    ok &= expect_equal("new record at capacity is not retained", contains(&list, 0, 999), 0);
    ok &= expect_equal("count remains capped", list.count, ACK_MAX_RECORDS);

    if (ok) {
        printf("RESULT confirmed: bounded ACK list silently drops new records at capacity and carries no acknowledged-state priority metadata\n");
    }
    else {
        printf("RESULT failed\n");
    }

    free_list(&list);
    return ok ? 0 : 1;
}
