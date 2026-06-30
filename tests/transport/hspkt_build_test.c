#include "test.h"

/* Derive a pair of Handshake-level keys (same type as Initial keys; the
 * derivation label differs in production but the codec is identical). */
static void hspkt_keys(quic_initial_keys *k, quic_aes128 *hp)
{
    const u8 dcid[8] = {0x83,0x94,0xc8,0xf0,0x3e,0x51,0x57,0x08};
    quic_initial_derive(dcid, 8, 1, k); /* server side */
    quic_aes128_init(hp, k->hp);
}

/* RFC 9000 17.2.4 / RFC 9001 5: build a Handshake packet, then open it with
 * the same keys; the CRYPTO payload comes back byte-for-byte. */
static void test_hspkt_build_roundtrip(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[5] = {0xaa,0xbb,0xcc,0xdd,0xee};
    const u8 scid[3] = {0x01,0x02,0x03};
    /* CRYPTO frame (type 0x06) carrying "EE" (EncryptedExtensions stand-in) */
    const u8 frames[] = {0x06, 0x00, 0x02, 'E','E'};
    hspkt_keys(&k, &hp);

    u8 pkt[128];
    usz total = 0;
    CHECK(quic_hspkt_build(&k, &hp, dcid, 5, scid, 3, 9,
                           frames, sizeof(frames), pkt, sizeof(pkt), &total));
    /* RFC 9000 17.2.4 complete header: byte0(1)+version(4)+dcid_len(1)+dcid(5)
     * +scid_len(1)+scid(3)+Length(1-byte varint)+pn(4) = 20, then payload+tag.
     * No Token field for Handshake. */
    CHECK(total == 20u + sizeof(frames) + 16u);

    const u8 *out = 0;
    usz olen = 0;
    CHECK(quic_hspkt_open(&k, &hp, pkt, total, 5, &out, &olen));
    CHECK(olen == sizeof(frames));
    for (usz i = 0; i < sizeof(frames); i++) CHECK(out[i] == frames[i]);
}

/* RFC 9000 17.2: long-header form (high bit set) with Handshake type bits
 * (5-4 = 0b10). After header protection the low 4 bits are masked, but the
 * top nibble (0b1110) is in the clear. */
static void test_hspkt_build_byte0(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {1,2,3,4};
    const u8 frames[] = {0x06, 0x00, 0x01, 'X'};
    hspkt_keys(&k, &hp);

    u8 pkt[128];
    usz total = 0;
    CHECK(quic_hspkt_build(&k, &hp, dcid, 4, 0, 0, 1,
                           frames, sizeof(frames), pkt, sizeof(pkt), &total));
    CHECK((pkt[0] & 0x80) == 0x80);       /* long header form */
    CHECK((pkt[0] & 0x30) == 0x20);       /* type bits = Handshake (0x2) */
}

/* A tampered ciphertext byte makes open fail (AEAD authentication). */
static void test_hspkt_build_tamper(void)
{
    quic_initial_keys k;
    quic_aes128 hp;
    const u8 dcid[4] = {9,8,7,6};
    const u8 frames[] = {0x06, 0x00, 0x02, 'h','i'};
    hspkt_keys(&k, &hp);

    u8 pkt[128];
    usz total = 0;
    CHECK(quic_hspkt_build(&k, &hp, dcid, 4, 0, 0, 3,
                           frames, sizeof(frames), pkt, sizeof(pkt), &total));
    pkt[total - 1] ^= 0x01;
    const u8 *out = 0;
    usz olen = 0;
    CHECK(!quic_hspkt_open(&k, &hp, pkt, total, 4, &out, &olen));
}

void test_hspkt_build(void)
{
    test_hspkt_build_roundtrip();
    test_hspkt_build_byte0();
    test_hspkt_build_tamper();
}
