#include "test.h"

static void test_version_reserved(void) {
  CHECK(version_is_reserved(0x0a0a0a0a) == 1);
  CHECK(version_is_reserved(0x1a2a3a4a) == 1);
  CHECK(version_is_reserved(VERSION_1) == 0);
  CHECK(version_is_reserved(VERSION_2) == 0);
}

static void test_version_info_roundtrip(void) {
  version_info in = {.chosen = VERSION_1, .n_available = 2};
  in.available[0] = VERSION_1;
  in.available[1] = VERSION_2;
  u8  buf[64];
  usz w = version_info_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == TP_VERSION_INFORMATION);

  version_info out;
  usz          r = version_info_decode(buf, w, &out);
  CHECK(r == w && out.chosen == VERSION_1 && out.n_available == 2);
  CHECK(out.available[0] == VERSION_1 && out.available[1] == VERSION_2);
}

static void test_version_info_truncated(void) {
  version_info in = {.chosen = VERSION_2, .n_available = 1};
  in.available[0] = VERSION_2;
  u8           buf[64];
  usz          w = version_info_encode(buf, sizeof(buf), &in);
  version_info out;
  CHECK(version_info_decode(buf, w - 1, &out) == 0);
}

/* RFC 9368 3: encode refuses an over-long Available list or a buffer too
 * small for the id, the length, or the value; decode refuses a missing id,
 * a different parameter id, and a missing length. */
static void test_version_info_bounds(void) {
  version_info    in    = {.chosen = VERSION_1, .n_available = 1};
  version_info    many  = {.chosen = VERSION_1};
  static const u8 id[]  = {TP_VERSION_INFORMATION};
  static const u8 oth[] = {0x12, 0x04, 0, 0, 0, 1};
  u8              buf[10];
  version_info    out;
  many.n_available = VI_MAX_AVAILABLE + 1;
  in.available[0]  = VERSION_1;
  {
    u8 big[128]; /* room even for 17 entries: only the count bound refuses */
    CHECK(version_info_encode(big, sizeof big, &many) == 0);
  }
  CHECK(version_info_encode(buf, 0, &in) == 0);
  CHECK(version_info_encode(buf, 1, &in) == 0);
  CHECK(version_info_encode(buf, sizeof buf - 1, &in) == 0); /* 2 + 8 */
  CHECK(version_info_encode(buf, sizeof buf, &in) == sizeof buf);
  CHECK(version_info_decode(id, 0, &out) == 0);
  CHECK(version_info_decode(oth, sizeof oth, &out) == 0);
  CHECK(version_info_decode(id, sizeof id, &out) == 0);
}

void test_version(void) {
  test_version_reserved();
  test_version_info_roundtrip();
  test_version_info_truncated();
  test_version_info_bounds();
}
