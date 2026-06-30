#include "test.h"
#include "transport/packet/header/shorthdr/shorthdr.h"
#include "spin/spin.h"

/* RFC 9000 17.3.1: byte0 = 0 1 S R R K P P. */
static void test_shorthdr_byte0_bits(void)
{
    /* fixed bit set, short form (bit7=0), reserved (0x18) clear */
    CHECK(quic_shorthdr_byte0(0, 0, 1) == 0x40);
    CHECK((quic_shorthdr_byte0(0, 0, 1) & 0x80) == 0);
    CHECK((quic_shorthdr_byte0(0, 0, 4) & 0x18) == 0);

    /* spin -> bit5 (0x20) */
    CHECK((quic_shorthdr_byte0(1, 0, 1) & 0x20) == 0x20);
    CHECK((quic_shorthdr_byte0(0, 0, 1) & 0x20) == 0x00);

    /* key phase -> bit2 (0x04) */
    CHECK((quic_shorthdr_byte0(0, 1, 1) & 0x04) == 0x04);
    CHECK((quic_shorthdr_byte0(0, 0, 1) & 0x04) == 0x00);

    /* pn_len-1 in low two bits */
    CHECK((quic_shorthdr_byte0(0, 0, 1) & 0x03) == 0);
    CHECK((quic_shorthdr_byte0(0, 0, 2) & 0x03) == 1);
    CHECK((quic_shorthdr_byte0(0, 0, 4) & 0x03) == 3);

    /* non-1 spin/key_phase still map to a single bit */
    CHECK((quic_shorthdr_byte0(7, 0, 1) & 0x20) == 0x20);
    CHECK((quic_shorthdr_byte0(0, 7, 1) & 0x04) == 0x04);
}

/* Layout: byte0, then DCID, then pn in pn_len big-endian bytes. */
static void test_shorthdr_build_layout(void)
{
    u8 dcid[4] = {0xAA, 0xBB, 0xCC, 0xDD};
    u8 out[16];
    usz n = 0;

    CHECK(quic_shorthdr_build(1, 1, dcid, 4, 0x010203, 4, out, sizeof out, &n));
    CHECK(n == 1 + 4 + 4);
    CHECK(out[0] == quic_shorthdr_byte0(1, 1, 4));
    CHECK(out[1] == 0xAA && out[2] == 0xBB && out[3] == 0xCC && out[4] == 0xDD);
    /* pn 0x00010203 big-endian over 4 bytes */
    CHECK(out[5] == 0x00 && out[6] == 0x01 && out[7] == 0x02 && out[8] == 0x03);
}

/* Bad args and no-room return 0. */
static void test_shorthdr_build_reject(void)
{
    u8 dcid[2] = {1, 2};
    u8 out[8];
    usz n = 0;

    CHECK(quic_shorthdr_build(0, 0, dcid, 2, 1, 0, out, sizeof out, &n) == 0);
    CHECK(quic_shorthdr_build(0, 0, dcid, 2, 1, 5, out, sizeof out, &n) == 0);
    /* needs 1 + 2 + 4 = 7 bytes; give 6 */
    CHECK(quic_shorthdr_build(0, 0, dcid, 2, 1, 4, out, 6, &n) == 0);
}

/* Round trip: read spin/key_phase/pn_len/pn back from the built bytes. */
static void test_shorthdr_roundtrip(void)
{
    u8 dcid[3] = {0x11, 0x22, 0x33};
    u8 out[16];
    usz n = 0;

    CHECK(quic_shorthdr_build(1, 1, dcid, 3, 0xABCD, 2, out, sizeof out, &n));
    CHECK(quic_spin_get(out[0]) == 1);
    CHECK(((out[0] >> 2) & 1) == 1);          /* key phase */
    CHECK((out[0] & 0x03) + 1 == 2);          /* pn_len */
    /* pn recovered from the 2 trailing bytes (after byte0 + 3 DCID) */
    CHECK(((u64)out[4] << 8 | out[5]) == 0xABCD);

    CHECK(quic_shorthdr_build(0, 0, dcid, 3, 0x7F, 1, out, sizeof out, &n));
    CHECK(quic_spin_get(out[0]) == 0);
    CHECK(((out[0] >> 2) & 1) == 0);
    CHECK((out[0] & 0x03) + 1 == 1);
    CHECK(out[4] == 0x7F);
}

void test_shorthdr(void)
{
    test_shorthdr_byte0_bits();
    test_shorthdr_build_layout();
    test_shorthdr_build_reject();
    test_shorthdr_roundtrip();
}
