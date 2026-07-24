#include "test.h"

/* RFC 7541 5.1: 1337 with a 5-bit prefix encodes to 0x1F 0x9A 0x0A. */
static void test_qpack_integer_vector(void) {
  u8             buf[8];
  quic_qpack_pfx pfx = {5, 0};
  usz w = quic_qpack_int_encode(quic_mspan_of(buf, sizeof(buf)), pfx, 1337);
  CHECK(w == 3 && buf[0] == 0x1F && buf[1] == 0x9A && buf[2] == 0x0A);

  u64 v;
  usz r = quic_qpack_int_decode(quic_span_of(buf, w), 5, &v);
  CHECK(r == w && v == 1337);
}

/* Values across the prefix boundary round-trip. */
static void test_qpack_integer_roundtrip(void) {
  u64 cases[] = {0, 10, 30, 31, 42, 1337, 100000};
  for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    u8             buf[12];
    u64            v;
    quic_qpack_pfx pfx = {5, 0};
    usz            w =
        quic_qpack_int_encode(quic_mspan_of(buf, sizeof(buf)), pfx, cases[i]);
    usz r = quic_qpack_int_decode(quic_span_of(buf, w), 5, &v);
    CHECK(w != 0 && r == w && v == cases[i]);
  }
}

/* RFC 9204 4.1.1 (9204-023): the format must carry integers up to and
 * including 62 bits (the same ceiling QUIC's own varint uses) -- round-trip
 * at the boundary itself (2^62 - 1) and one below it, across a couple of
 * prefix widths so the boundary is not an artifact of one particular
 * prefix_bits choice. */
static void test_qpack_integer_62bit_boundary(void) {
  u64 cases[]         = {((u64)1 << 62) - 2, ((u64)1 << 62) - 1};
  u8  prefix_widths[] = {5, 7};
  for (usz p = 0; p < sizeof(prefix_widths) / sizeof(prefix_widths[0]); p++) {
    quic_qpack_pfx pfx = {prefix_widths[p], 0};
    for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      u8  buf[16];
      u64 v;
      usz w =
          quic_qpack_int_encode(quic_mspan_of(buf, sizeof(buf)), pfx, cases[i]);
      usz r = quic_qpack_int_decode(quic_span_of(buf, w), pfx.bits, &v);
      CHECK(w != 0 && r == w && v == cases[i]);
    }
  }
}

/* A raw string literal round-trips; truncation is rejected. */
static void test_qpack_string(void) {
  const u8  s[] = {'h', 'e', 'l', 'l', 'o'};
  u8        buf[16], out[16];
  quic_obuf ob = quic_obuf_of(out, sizeof(out));
  usz       w  = quic_qpack_string_encode(
      quic_mspan_of(buf, sizeof(buf)), quic_span_of(s, 5));
  CHECK(w != 0);
  usz r = quic_qpack_string_decode(quic_span_of(buf, w), &ob);
  CHECK(r == w && ob.len == 5 && out[0] == 'h' && out[4] == 'o');
  CHECK(quic_qpack_string_decode(quic_span_of(buf, w - 1), &ob) == 0);
}

/* The static table resolves known indices and finds known pairs. */
static void test_qpack_static_table(void) {
  const char *name, *value;
  CHECK(quic_qpack_static_get(17, &name, &value) == 1);
  CHECK(str_eq(name, ":method") && str_eq(value, "GET"));
  CHECK(quic_qpack_static_get(QUIC_QPACK_STATIC_COUNT, &name, &value) == 0);

  CHECK(quic_qpack_static_find(":method", "GET") == 17);
  CHECK(quic_qpack_static_find(":status", "200") == 25);
  CHECK(quic_qpack_static_find("nonexistent-header", "x") == -1);
}

void test_qpack(void) {
  test_qpack_integer_vector();
  test_qpack_integer_roundtrip();
  test_qpack_integer_62bit_boundary();
  test_qpack_string();
  test_qpack_static_table();
}
