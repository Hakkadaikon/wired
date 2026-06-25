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

/* Recovery is only guaranteed inside the open window (distance < win/2).
 * At exactly win/2 below expected the candidate is ambiguous and recovery
 * does NOT match; the encoder avoids this by picking a longer length.
 * (Lean P1 boundary: recover(0x69,1,1000)=1129, not the 873 that is 128
 * below expected.) */
static void test_pnum_window_boundary(void)
{
    const u8 trunc[1] = {0x69}; /* 873 & 0xFF, full 873 is win/2 below */
    CHECK(quic_pnum_decode(trunc, 1, 1000) == 1129);
    CHECK(quic_pnum_decode(trunc, 1, 1000) != 873);
    /* one more byte of length resolves it unambiguously */
    u8 buf[2];
    quic_pnum_encode(buf, 873, 2);
    CHECK(quic_pnum_decode(buf, 2, 1000) == 873);
}

/* The decoder must lift (+win) when the candidate sits a window below
 * expected, and lower (-win) when it sits a window above. */
static void test_pnum_lift_lower(void)
{
    /* lift: expected 0x181, candidate 0x100 is a full window below -> +win */
    const u8 lo[1] = {0x00};
    CHECK(quic_pnum_decode(lo, 1, 0x180) == 0x200);
    /* lower: expected 0x101, candidate 0x1FE is a window above -> -win */
    const u8 hi[1] = {0xFE};
    CHECK(quic_pnum_decode(hi, 1, 0x100) == 0xFE);
}

void test_pnum(void)
{
    test_pnum_rfc_decode();
    test_pnum_len();
    test_pnum_roundtrip();
    test_pnum_window_boundary();
    test_pnum_lift_lower();
}
