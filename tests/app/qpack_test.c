#include "test.h"

/* RFC 7541 5.1: 1337 with a 5-bit prefix encodes to 0x1F 0x9A 0x0A. */
static void test_qpack_integer_vector(void) {
  u8        buf[8];
  qpack_pfx pfx = {5, 0};
  usz       w   = qpack_int_encode(wired_mspan_of(buf, sizeof(buf)), pfx, 1337);
  CHECK(w == 3 && buf[0] == 0x1F && buf[1] == 0x9A && buf[2] == 0x0A);

  u64 v;
  usz r = qpack_int_decode(wired_span_of(buf, w), 5, &v);
  CHECK(r == w && v == 1337);
}

/* Values across the prefix boundary round-trip. */
static void test_qpack_integer_roundtrip(void) {
  u64 cases[] = {0, 10, 30, 31, 42, 1337, 100000};
  for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    u8        buf[12];
    u64       v;
    qpack_pfx pfx = {5, 0};
    usz w = qpack_int_encode(wired_mspan_of(buf, sizeof(buf)), pfx, cases[i]);
    usz r = qpack_int_decode(wired_span_of(buf, w), 5, &v);
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
    qpack_pfx pfx = {prefix_widths[p], 0};
    for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      u8  buf[16];
      u64 v;
      usz w = qpack_int_encode(wired_mspan_of(buf, sizeof(buf)), pfx, cases[i]);
      usz r = qpack_int_decode(wired_span_of(buf, w), pfx.bits, &v);
      CHECK(w != 0 && r == w && v == cases[i]);
    }
  }
}

/* A raw string literal round-trips; truncation is rejected. */
static void test_qpack_string(void) {
  const u8   s[] = {'h', 'e', 'l', 'l', 'o'};
  u8         buf[16], out[16];
  wired_obuf ob = obuf_of(out, sizeof(out));
  usz        w  = qpack_string_encode(
      wired_mspan_of(buf, sizeof(buf)), wired_span_of(s, 5));
  CHECK(w != 0);
  usz r = qpack_string_decode(wired_span_of(buf, w), &ob);
  CHECK(r == w && ob.len == 5 && out[0] == 'h' && out[4] == 'o');
  CHECK(qpack_string_decode(wired_span_of(buf, w - 1), &ob) == 0);
}

/* The static table resolves known indices and finds known pairs. */
static void test_qpack_static_table(void) {
  const char *name, *value;
  CHECK(qpack_static_get(17, &name, &value) == 1);
  CHECK(str_eq(name, ":method") && str_eq(value, "GET"));
  CHECK(qpack_static_get(QPACK_STATIC_COUNT, &name, &value) == 0);

  CHECK(qpack_static_find(":method", "GET") == 17);
  CHECK(qpack_static_find(":status", "200") == 25);
  CHECK(qpack_static_find("nonexistent-header", "x") == -1);
}

/* Pinning: GHSA-mj42-367w-cf98 -- a raw string literal whose declared length
 * exceeds the caller's fixed destination capacity must be rejected before
 * any copy, never resized to fit (V-0426). The source really carries the
 * 200 bytes, so only the capacity check stands between them and dst. */
static void test_qpack_string_decode_oversized_length_rejected(void) {
  u8        buf[256];
  u8        payload[200];
  qpack_pfx pfx = {7, 0};
  usz       w   = qpack_int_encode(wired_mspan_of(buf, sizeof buf), pfx, 200);
  CHECK(w != 0);
  for (usz i = 0; i < sizeof payload; i++) payload[i] = (u8)i;
  CHECK(bytes_put(
      wired_mspan_of(buf, sizeof buf), &w,
      wired_span_of(payload, sizeof payload)));

  u8         out[256]; /* backing is wide; the advertised cap is 16 */
  wired_obuf ob = obuf_of(out, 16);
  CHECK(qpack_string_decode(wired_span_of(buf, w), &ob) == 0);
  CHECK(ob.len == 0);
}

/* CVE-2024-34161 class (V-0433): a length header that claims more octets
 * than actually follow in the input span must be rejected by str_value's
 * own `h->off + h->len > buf.n` check, not merely by the destination
 * capacity. The declared length (50) is well within the 64-byte cap, but
 * only 3 bytes actually follow the header in buf -- isolating the
 * input-span bounds check from the separate output-capacity check that
 * test_qpack_string_decode_oversized_length_rejected already covers. */
static void test_qpack_string_decode_truncated_input_rejected(void) {
  u8        buf[8];
  qpack_pfx pfx = {7, 0};
  usz       w   = qpack_int_encode(wired_mspan_of(buf, sizeof buf), pfx, 50);
  CHECK(w != 0);
  buf[w]     = 'a';
  buf[w + 1] = 'b';
  buf[w + 2] = 'c'; /* only 3 payload bytes follow, not the claimed 50 */

  u8         out[64];
  wired_obuf ob = obuf_of(out, sizeof out);
  CHECK(qpack_string_decode(wired_span_of(buf, w + 3), &ob) == 0);
  CHECK(ob.len == 0);
}

/* Pinning: RFC 9204 4.1.1 -- the continuation encoding must not accept a
 * value beyond the 64-bit ceiling; take_group's `m > 56` guard rejects a
 * tenth continuation group (shift 63) even when a terminating byte follows
 * (V-0477). */
static void test_qpack_integer_decode_64bit_overflow_rejected(void) {
  /* prefix, nine continuation groups (shifts 0..56), then a terminator at
   * shift 63 -- without the guard this would decode "successfully". */
  u8  buf[11] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
                 0xff, 0xff, 0xff, 0xff, 0x01};
  u64 v;
  CHECK(qpack_int_decode(wired_span_of(buf, sizeof buf), 7, &v) == 0);
}

/* Pinning: CVE-2024-32760-class -- every string-decode write goes through a
 * capacity-checked path: for a spread of declared lengths (bytes really
 * present) against a small fixed destination, decode either fails closed or
 * never writes past dst's cap; a length claiming more bytes than the source
 * holds fails closed too (V-0430). */
static void test_qpack_string_decode_fuzz_no_overflow(void) {
  static const usz lens[] = {0, 1, 4, 5, 15, 16, 17, 200, 1000};
  static u8        src[1024], dst[1024]; /* wide backings: cap is 16 */
  for (usz i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
    qpack_pfx pfx = {7, 0};
    usz w = qpack_int_encode(wired_mspan_of(src, sizeof src), pfx, lens[i]);
    wired_obuf ob = obuf_of(dst, 16);
    usz        r;
    w += lens[i]; /* the declared bytes are present (src is zeroed) */
    r = qpack_string_decode(wired_span_of(src, w), &ob);
    CHECK(r == 0 || ob.len <= 16);
    CHECK((r != 0) == (lens[i] <= 16));
    /* same header, one source byte short: truncated, must fail closed. */
    ob = obuf_of(dst, 16);
    CHECK(qpack_string_decode(wired_span_of(src, w - 1), &ob) == 0);
  }
}

void test_qpack(void) {
  test_qpack_integer_vector();
  test_qpack_integer_roundtrip();
  test_qpack_integer_62bit_boundary();
  test_qpack_string();
  test_qpack_static_table();
  test_qpack_string_decode_oversized_length_rejected();
  test_qpack_string_decode_truncated_input_rejected();
  test_qpack_integer_decode_64bit_overflow_rejected();
  test_qpack_string_decode_fuzz_no_overflow();
}
