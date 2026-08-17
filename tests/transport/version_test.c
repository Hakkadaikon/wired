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

void test_version(void) {
  test_version_reserved();
  test_version_info_roundtrip();
  test_version_info_truncated();
}
