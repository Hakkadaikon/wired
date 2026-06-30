#include "test.h"

/* RFC 9000 10.3: a stored CID->token is found; an unknown CID is not. */
void test_sresetdrive_tokenmap(void)
{
    quic_sresetdrive_map m;
    quic_sresetdrive_map_init(&m);

    const u8 cid_a[4] = {1, 2, 3, 4};
    const u8 cid_b[5] = {1, 2, 3, 4, 5}; /* prefix of cid_a, longer */
    u8 tok_a[QUIC_SRESETDRIVE_TOKEN], tok_b[QUIC_SRESETDRIVE_TOKEN];
    for (u8 i = 0; i < QUIC_SRESETDRIVE_TOKEN; i++) { tok_a[i] = i; tok_b[i] = (u8)(100 + i); }

    CHECK(quic_sresetdrive_map_add(&m, cid_a, 4, tok_a) == 1);
    CHECK(quic_sresetdrive_map_add(&m, cid_b, 5, tok_b) == 1);

    const u8 *got = 0;
    CHECK(quic_sresetdrive_map_find(&m, cid_a, 4, &got) == 1);
    for (u8 i = 0; i < QUIC_SRESETDRIVE_TOKEN; i++) CHECK(got[i] == tok_a[i]);

    /* same prefix, different length must not collide */
    CHECK(quic_sresetdrive_map_find(&m, cid_b, 5, &got) == 1);
    for (u8 i = 0; i < QUIC_SRESETDRIVE_TOKEN; i++) CHECK(got[i] == tok_b[i]);

    const u8 unknown[4] = {9, 9, 9, 9};
    CHECK(quic_sresetdrive_map_find(&m, unknown, 4, &got) == 0);

    /* over-long CID is rejected, not stored */
    u8 big[QUIC_SRESETDRIVE_MAX_CID + 1] = {0};
    CHECK(quic_sresetdrive_map_add(&m, big, QUIC_SRESETDRIVE_MAX_CID + 1, tok_a) == 0);
}
