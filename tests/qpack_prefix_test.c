#include "test.h"

/* The minimal prefix for an empty dynamic table: Required Insert Count 0 and
 * Delta Base 0 encode to two zero bytes and round-trip (RFC 9204 4.5.1). */
static void test_qpack_prefix_empty(void)
{
    quic_qpack_prefix in = {.required_insert_count = 0, .sign = 0, .delta_base = 0};
    u8 buf[8];
    usz w = quic_qpack_prefix_encode(buf, sizeof(buf), &in);
    CHECK(w == 2 && buf[0] == 0x00 && buf[1] == 0x00);

    quic_qpack_prefix out;
    usz r = quic_qpack_prefix_decode(buf, w, &out);
    CHECK(r == w && out.required_insert_count == 0);
    CHECK(out.sign == 0 && out.delta_base == 0);
}

/* Non-zero counts, the Sign bit, and multi-byte fields round-trip. */
static void test_qpack_prefix_roundtrip(void)
{
    quic_qpack_prefix cases[] = {
        {.required_insert_count = 1, .sign = 0, .delta_base = 0},
        {.required_insert_count = 5, .sign = 1, .delta_base = 2},
        {.required_insert_count = 1000, .sign = 1, .delta_base = 300},
    };
    for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u8 buf[16];
        usz w = quic_qpack_prefix_encode(buf, sizeof(buf), &cases[i]);
        CHECK(w != 0);
        quic_qpack_prefix out;
        usz r = quic_qpack_prefix_decode(buf, w, &out);
        CHECK(r == w);
        CHECK(out.required_insert_count == cases[i].required_insert_count);
        CHECK(out.sign == cases[i].sign && out.delta_base == cases[i].delta_base);
    }
}

/* A prefix cut between its two integers is rejected. */
static void test_qpack_prefix_truncated(void)
{
    quic_qpack_prefix in = {.required_insert_count = 1000, .sign = 1, .delta_base = 300};
    u8 buf[16];
    usz w = quic_qpack_prefix_encode(buf, sizeof(buf), &in);
    quic_qpack_prefix out;
    CHECK(quic_qpack_prefix_decode(buf, w - 1, &out) == 0);
    CHECK(quic_qpack_prefix_decode(buf, 0, &out) == 0);
}

void test_qpack_prefix(void)
{
    test_qpack_prefix_empty();
    test_qpack_prefix_roundtrip();
    test_qpack_prefix_truncated();
}
