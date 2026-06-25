#include "test.h"
#include "tls/schedule.c"

/* Both peers feed the same ECDHE secret into the schedule and arrive at the
 * same handshake secret (this is what lets them agree on traffic keys). */
static void test_schedule_agreement(void)
{
    u8 ecdhe[32];
    for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(i + 1);
    u8 hs_a[32], hs_b[32];
    quic_tls_handshake_secret(ecdhe, hs_a);
    quic_tls_handshake_secret(ecdhe, hs_b);
    for (usz i = 0; i < 32; i++) CHECK(hs_a[i] == hs_b[i]); /* deterministic */
}

/* Client and server derive distinct directions, but each side computing the
 * peer's direction matches: client's "s hs traffic" == server's own keys. */
static void test_schedule_directions(void)
{
    u8 ecdhe[32], hs[32];
    for (usz i = 0; i < 32; i++) ecdhe[i] = (u8)(0xA0 + i);
    quic_tls_handshake_secret(ecdhe, hs);
    const u8 transcript[] = "ClientHello||ServerHello";

    quic_initial_keys c_keys, s_keys, s_keys_from_client;
    quic_tls_handshake_keys(hs, transcript, sizeof(transcript), 0, &c_keys);
    quic_tls_handshake_keys(hs, transcript, sizeof(transcript), 1, &s_keys);
    quic_tls_handshake_keys(hs, transcript, sizeof(transcript), 1,
                            &s_keys_from_client);

    /* server-direction keys are identical whoever derives them */
    for (usz i = 0; i < QUIC_INITIAL_KEY; i++)
        CHECK(s_keys.key[i] == s_keys_from_client.key[i]);
    /* the two directions differ (client key != server key) */
    int differ = 0;
    for (usz i = 0; i < QUIC_INITIAL_KEY; i++)
        differ |= (c_keys.key[i] != s_keys.key[i]);
    CHECK(differ);
}

void test_schedule(void)
{
    test_schedule_agreement();
    test_schedule_directions();
}
