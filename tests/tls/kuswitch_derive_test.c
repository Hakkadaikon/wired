#include "test.h"

/* RFC 9001 6.1: next keys come from the next secret (kuderive), key/iv are
 * re-derived from it, and hp is left unchanged. */
void test_kuswitch_derive(void)
{
    u8 cur[32];
    for (usz i = 0; i < 32; i++) cur[i] = (u8)i;

    quic_initial_keys next;
    for (usz i = 0; i < QUIC_INITIAL_HP; i++) next.hp[i] = 0xAB; /* sentinel */
    u8 next_secret[32];
    quic_kuswitch_next_keys(cur, &next, next_secret);

    /* next_secret matches the standalone kuderive output (re-uses it) */
    u8 expect_secret[32];
    quic_ku_next_secret(cur, expect_secret);
    for (usz i = 0; i < 32; i++) CHECK(next_secret[i] == expect_secret[i]);

    /* key/iv match Expand-Label from that secret */
    u8 ek[QUIC_INITIAL_KEY], ev[QUIC_INITIAL_IV];
    quic_hkdf_expand_label(expect_secret, "quic key", 8, 0, 0, ek,
                           QUIC_INITIAL_KEY);
    quic_hkdf_expand_label(expect_secret, "quic iv", 7, 0, 0, ev,
                           QUIC_INITIAL_IV);
    for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(next.key[i] == ek[i]);
    for (usz i = 0; i < QUIC_INITIAL_IV; i++) CHECK(next.iv[i] == ev[i]);

    /* RFC 9001 6.1: hp untouched */
    for (usz i = 0; i < QUIC_INITIAL_HP; i++) CHECK(next.hp[i] == 0xAB);

    /* deterministic */
    quic_initial_keys again;
    u8 again_secret[32];
    quic_kuswitch_next_keys(cur, &again, again_secret);
    for (usz i = 0; i < QUIC_INITIAL_KEY; i++) CHECK(again.key[i] == next.key[i]);
}
