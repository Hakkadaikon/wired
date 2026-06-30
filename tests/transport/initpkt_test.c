#include "test.h"

/* RFC 9001 A.1: DCID 0x8394c8f03e515708 yields the known client Initial key,
 * iv, and hp. quic_initpkt_derive must reproduce these for the client side. */
static void test_initpkt_keys_rfc(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_initial_keys ck, sk;
    quic_initpkt_derive(dcid, 8, &ck, &sk);

    const u8 want_key[16] = {0x1f,0x36,0x96,0x13,0xdd,0x76,0xd5,0x46,
                             0x77,0x30,0xef,0xcb,0xe3,0xb1,0xa2,0x2d};
    const u8 want_iv[12] = {0xfa,0x04,0x4b,0x2f,0x42,0xa3,0xfd,0x3b,
                            0x46,0xfb,0x25,0x5c};
    const u8 want_hp[16] = {0x9f,0x50,0x44,0x9e,0x04,0xa0,0xe8,0x10,
                            0x28,0x3a,0x1e,0x99,0x33,0xad,0xed,0xd2};
    for (usz i = 0; i < 16; i++) CHECK(ck.key[i] == want_key[i]);
    for (usz i = 0; i < 12; i++) CHECK(ck.iv[i] == want_iv[i]);
    for (usz i = 0; i < 16; i++) CHECK(ck.hp[i] == want_hp[i]);

    /* server keys differ from client keys (RFC 9001 5.2 distinct labels) */
    CHECK(sk.key[0] != ck.key[0] || sk.key[1] != ck.key[1]);
}

/* Build a protected Initial from a DCID, then open it with the same DCID:
 * the CRYPTO payload comes back byte-for-byte (seal then open = id). */
static void test_initpkt_roundtrip(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    const u8 scid[4] = {0xde,0xad,0xbe,0xef};
    const u8 ch[] = {'C','l','i','e','n','t','H','e','l','l','o'};

    u8 pkt[1300];
    usz total = 0;
    CHECK(quic_initpkt_build(dcid, 8, scid, 4, ch, sizeof(ch), 2,
                             pkt, sizeof(pkt), &total));
    /* RFC 9000 14.1: the datagram reaches the 1200-byte minimum */
    CHECK(total >= 1200);

    const u8 *crypto = 0;
    usz clen = 0;
    CHECK(quic_initpkt_open(dcid, 8, pkt, total, 2, &crypto, &clen));
    /* the recovered frames begin with a CRYPTO frame (type 0x06) carrying CH */
    CHECK(crypto[0] == 0x06);
    /* CRYPTO frame: type, offset varint (0x00), length varint (0x0b), then CH */
    CHECK(crypto[1] == 0x00 && crypto[2] == 0x0b);
    for (usz i = 0; i < sizeof(ch); i++) CHECK(crypto[3 + i] == ch[i]);
}

/* A tampered ciphertext byte makes open fail (AEAD authentication). */
static void test_initpkt_tamper(void)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    const u8 ch[] = {'h','i'};
    u8 pkt[1300];
    usz total = 0;
    CHECK(quic_initpkt_build(dcid, 8, 0, 0, ch, sizeof(ch), 7,
                             pkt, sizeof(pkt), &total));
    pkt[total - 1] ^= 0x01;
    const u8 *crypto = 0;
    usz clen = 0;
    CHECK(!quic_initpkt_open(dcid, 8, pkt, total, 7, &crypto, &clen));
}

void test_initpkt(void)
{
    test_initpkt_keys_rfc();
    test_initpkt_roundtrip();
    test_initpkt_tamper();
}
