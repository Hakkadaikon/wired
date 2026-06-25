#include "test.h"
#include "packet/pnum.c"

/* RFC 9000 A.3 worked example: largest_pn 0xa82f30ea, received 2-byte
 * truncated 0x9b32 -> full packet number 0xa82f9b32. */
static void test_pnum_rfc_decode(void)
{
    const u8 trunc[2] = {0x9b, 0x32};
    CHECK(quic_pnum_decode(trunc, 2, 0xa82f30ea) == 0xa82f9b32);
}

static void test_pnum_len(void)
{
    /* small range -> 1 byte; just over -> 2; etc. */
    CHECK(quic_pnum_len(0, ~0ULL) == 1);          /* range 1 */
    CHECK(quic_pnum_len(0x4000, 0) == 2);         /* 2*range > 0x7FFF */
    CHECK(quic_pnum_len(0x40000000, 0) == 4);     /* 2*range > 0x7FFFFFFF */
}

static void test_pnum_roundtrip(void)
{
    u64 largest = 1000;
    u64 cases[] = {1001, 1500, 2000, 33000, 1000000};
    for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u8 buf[4];
        usz n = quic_pnum_len(cases[i], largest);
        quic_pnum_encode(buf, cases[i], n);
        u64 got = quic_pnum_decode(buf, n, largest);
        CHECK(got == cases[i]);
    }
}

void test_pnum(void)
{
    test_pnum_rfc_decode();
    test_pnum_len();
    test_pnum_roundtrip();
}
