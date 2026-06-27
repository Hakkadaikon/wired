#include "test.h"

/* RFC 7541 5.1: 1337 with a 5-bit prefix encodes to 0x1F 0x9A 0x0A. */
static void test_qpack_integer_vector(void)
{
    u8 buf[8];
    usz w = quic_qpack_int_encode(buf, sizeof(buf), 5, 0, 1337);
    CHECK(w == 3 && buf[0] == 0x1F && buf[1] == 0x9A && buf[2] == 0x0A);

    u64 v;
    usz r = quic_qpack_int_decode(buf, w, 5, &v);
    CHECK(r == w && v == 1337);
}

/* Values across the prefix boundary round-trip. */
static void test_qpack_integer_roundtrip(void)
{
    u64 cases[] = {0, 10, 30, 31, 42, 1337, 100000};
    for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        u8 buf[12];
        u64 v;
        usz w = quic_qpack_int_encode(buf, sizeof(buf), 5, 0, cases[i]);
        usz r = quic_qpack_int_decode(buf, w, 5, &v);
        CHECK(w != 0 && r == w && v == cases[i]);
    }
}

/* A raw string literal round-trips; truncation is rejected. */
static void test_qpack_string(void)
{
    const u8 s[] = {'h', 'e', 'l', 'l', 'o'};
    u8 buf[16], out[16];
    usz olen;
    usz w = quic_qpack_string_encode(buf, sizeof(buf), s, 5);
    CHECK(w != 0);
    usz r = quic_qpack_string_decode(buf, w, out, sizeof(out), &olen);
    CHECK(r == w && olen == 5 && out[0] == 'h' && out[4] == 'o');
    CHECK(quic_qpack_string_decode(buf, w - 1, out, sizeof(out), &olen) == 0);
}

/* The static table resolves known indices and finds known pairs. */
static void test_qpack_static_table(void)
{
    const char *name, *value;
    CHECK(quic_qpack_static_get(17, &name, &value) == 1);
    CHECK(str_eq(name, ":method") && str_eq(value, "GET"));
    CHECK(quic_qpack_static_get(QUIC_QPACK_STATIC_COUNT, &name, &value) == 0);

    CHECK(quic_qpack_static_find(":method", "GET") == 17);
    CHECK(quic_qpack_static_find(":status", "200") == 25);
    CHECK(quic_qpack_static_find("nonexistent-header", "x") == -1);
}

void test_qpack(void)
{
    test_qpack_integer_vector();
    test_qpack_integer_roundtrip();
    test_qpack_string();
    test_qpack_static_table();
}
