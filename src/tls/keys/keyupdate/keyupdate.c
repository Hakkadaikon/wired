#include "tls/keys/keyupdate/keyupdate.h"

void quic_keyupdate_init(quic_keyupdate *k)
{
    k->gen = 0;
    k->lowest = 0;
    k->updating = 0;
}

u8 quic_keyupdate_phase(const quic_keyupdate *k)
{
    return (u8)(k->gen & 1);
}

/* Advance to the next generation, retaining exactly {gen-1, gen}. */
static void advance(quic_keyupdate *k)
{
    k->gen += 1;
    k->lowest = k->gen - 1;
}

int quic_keyupdate_initiate(quic_keyupdate *k)
{
    if (k->updating) return 0; /* prior update not yet acknowledged */
    advance(k);
    k->updating = 1;
    return 1;
}

void quic_keyupdate_acked(quic_keyupdate *k)
{
    k->updating = 0;
}

int quic_keyupdate_follow(quic_keyupdate *k)
{
    if (k->updating) return 0; /* wait for our own update to be acked first */
    advance(k);
    return 1;
}

int quic_keyupdate_can_decrypt(const quic_keyupdate *k, u64 g)
{
    return g >= k->lowest && g <= k->gen + 1;
}
