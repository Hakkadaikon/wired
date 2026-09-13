#include "test.h"

/* RFC 9000 Appendix A.1 sample encodings. */
static void test_varint_rfc_vectors(void) {
  u8  buf[8];
  u64 v;
  CHECK(varint_encode(buf, 37) == 1 && buf[0] == 0x25);
  CHECK(varint_encode(buf, 15293) == 2 && buf[0] == 0x7B && buf[1] == 0xBD);
  CHECK(
      varint_decode((const u8*)"\xc2\x19\x7c\x5e\xff\x14\xe8\x8c", 8, &v) ==
          8 &&
      v == 151288809941952652ULL);
  CHECK(
      varint_decode((const u8*)"\x9d\x7f\x3e\x7d", 4, &v) == 4 &&
      v == 494878333);
  CHECK(varint_decode((const u8*)"\x40\x25", 2, &v) == 2 && v == 37);
}

static void test_varint_roundtrip(void) {
  u64 cases[] = {0,      1,          0x3F,       0x40,      0x3FFF,
                 0x4000, 0x3FFFFFFF, 0x40000000, VARINT_MAX};
  for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    u8  buf[8];
    u64 out;
    usz w = varint_encode(buf, cases[i]);
    usz r = varint_decode(buf, w, &out);
    CHECK(w != 0 && r == w && out == cases[i]);
  }
  /* out of range */
  u8 buf[8];
  CHECK(varint_encode(buf, VARINT_MAX + 1) == 0);
}

static void test_varint_truncated(void) {
  u64 v;
  CHECK(varint_decode((const u8*)"", 0, &v) == 0);
  CHECK(varint_decode((const u8*)"\xc0", 1, &v) == 0); /* needs 8, has 1 */
}

/* CVE-2020-24944-class loop-DoS: varint_take must either advance the cursor
 * on success or fail cleanly on a truncated/malformed varint -- never leave
 * *off unmoved while reporting success, which is what would let a frame-
 * parse loop spin forever re-reading the same bytes. */
static void test_varint_take_advances_or_fails(void) {
  wired_span buf = wired_span_of((const u8*)"\x40\x25", 2);
  usz        off = 0;
  u64        v   = 0;
  CHECK(varint_take(buf, &off, &v) == 1);
  CHECK(off == 2 && v == 37); /* advanced by the full encoded width */

  /* truncated: a 2-byte-form prefix with no second byte. */
  wired_span trunc = wired_span_of((const u8*)"\x40", 1);
  usz        off2  = 0;
  CHECK(varint_take(trunc, &off2, &v) == 0);
  CHECK(off2 == 0); /* failure leaves the cursor exactly where it was */
}

void test_varint(void) {
  test_varint_rfc_vectors();
  test_varint_roundtrip();
  test_varint_truncated();
  test_varint_take_advances_or_fails();
}
