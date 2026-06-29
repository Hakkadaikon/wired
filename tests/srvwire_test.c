#include "test.h"

/* RFC 9000 17.2 / RFC 9001 5: server-direction handshake wire codec. A TLS
 * flight handed to a srvwire seal comes back byte-for-byte from the matching
 * open (seal then open = identity); a tampered byte fails AEAD; the wrong keys
 * fail to open. The seal/open glue (CRYPTO-frame emit + extract) is what the
 * server orchestrator does not own. */

/* RFC 9001 5.2: server Initial. Sealed under the server Initial key derived
 * from the client's DCID; opened with the same DCID recovers the ServerHello. */
static void test_srvwire_initial_roundtrip(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    const u8 scid[6] = {'S','R','V','C','I','D'};
    const u8 sh[] = {'S','e','r','v','e','r','H','e','l','l','o'};
    u8 pkt[1300];
    usz total = 0;
    CHECK(quic_srvwire_seal_initial(dcid, 8, scid, 6, 1, sh, sizeof(sh),
                                    pkt, sizeof(pkt), &total));
    CHECK(total > sizeof(sh)); /* header + AEAD tag overhead present */

    const u8 *tls = 0;
    usz tls_len = 0;
    CHECK(quic_srvwire_open_initial(dcid, 8, pkt, total, 1, &tls, &tls_len));
    CHECK(tls_len == sizeof(sh));
    for (usz i = 0; i < sizeof(sh); i++) CHECK(tls[i] == sh[i]);
}

/* A flipped ciphertext byte must fail AEAD on open. */
static void test_srvwire_initial_tamper(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    const u8 scid[6] = {'S','R','V','C','I','D'};
    const u8 sh[] = {'S','e','r','v','e','r','H','e','l','l','o'};
    u8 pkt[1300];
    usz total = 0;
    CHECK(quic_srvwire_seal_initial(dcid, 8, scid, 6, 1, sh, sizeof(sh),
                                    pkt, sizeof(pkt), &total));
    pkt[total - 1] ^= 0x01;
    const u8 *tls = 0;
    usz tls_len = 0;
    CHECK(!quic_srvwire_open_initial(dcid, 8, pkt, total, 1, &tls, &tls_len));
}

/* A different DCID derives different keys: open must fail. */
static void test_srvwire_initial_wrong_key(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    const u8 bad[8]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
    const u8 scid[6] = {'S','R','V','C','I','D'};
    const u8 sh[] = {'S','e','r','v','e','r','H','e','l','l','o'};
    u8 pkt[1300];
    usz total = 0;
    CHECK(quic_srvwire_seal_initial(dcid, 8, scid, 6, 1, sh, sizeof(sh),
                                    pkt, sizeof(pkt), &total));
    const u8 *tls = 0;
    usz tls_len = 0;
    CHECK(!quic_srvwire_open_initial(bad, 8, pkt, total, 1, &tls, &tls_len));
}

/* Shared Handshake keys for the round-trip tests (RFC 9001 5). */
static void hs_keys(quic_initial_keys *k, quic_aes128 *hp)
{
    for (usz i = 0; i < 16; i++) { k->key[i] = (u8)(0x10 + i); k->hp[i] = (u8)(0x90 + i); }
    for (usz i = 0; i < 12; i++) k->iv[i] = (u8)(0x30 + i);
    quic_aes128_init(hp, k->hp);
}

/* RFC 9001 5: Handshake flight. Sealed and opened under the same caller-
 * supplied directional keys recovers the EE/Cert/CV/Fin bytes. */
static void test_srvwire_handshake_roundtrip(void)
{
    const u8 dcid[6] = {'C','I','D','x','y','z'};
    const u8 scid[6] = {'S','R','V','C','I','D'};
    const u8 fl[] = {'E','E','C','e','r','t','C','V','F','i','n'};
    quic_initial_keys k;
    quic_aes128 hp;
    hs_keys(&k, &hp);
    u8 pkt[256];
    usz total = 0;
    CHECK(quic_srvwire_seal_handshake(&k, &hp, dcid, 6, scid, 6, 0,
                                      fl, sizeof(fl), pkt, sizeof(pkt), &total));
    const u8 *tls = 0;
    usz tls_len = 0;
    CHECK(quic_srvwire_open_handshake(&k, &hp, pkt, total, 6, &tls, &tls_len));
    CHECK(tls_len == sizeof(fl));
    for (usz i = 0; i < sizeof(fl); i++) CHECK(tls[i] == fl[i]);
}

/* Wrong Handshake keys must fail to open. */
static void test_srvwire_handshake_wrong_key(void)
{
    const u8 dcid[6] = {'C','I','D','x','y','z'};
    const u8 scid[6] = {'S','R','V','C','I','D'};
    const u8 fl[] = {'E','E','C','e','r','t','C','V','F','i','n'};
    quic_initial_keys k, bad;
    quic_aes128 hp, badhp;
    hs_keys(&k, &hp);
    hs_keys(&bad, &badhp);
    bad.key[0] ^= 0xff;
    u8 pkt[256];
    usz total = 0;
    CHECK(quic_srvwire_seal_handshake(&k, &hp, dcid, 6, scid, 6, 0,
                                      fl, sizeof(fl), pkt, sizeof(pkt), &total));
    const u8 *tls = 0;
    usz tls_len = 0;
    CHECK(!quic_srvwire_open_handshake(&bad, &hp, pkt, total, 6, &tls, &tls_len));
}

void test_srvwire(void)
{
    test_srvwire_initial_roundtrip();
    test_srvwire_initial_tamper();
    test_srvwire_initial_wrong_key();
    test_srvwire_handshake_roundtrip();
    test_srvwire_handshake_wrong_key();
}
