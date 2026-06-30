#include "test.h"

static void test_version_reserved(void) {
  CHECK(quic_version_is_reserved(0x0a0a0a0a) == 1);
  CHECK(quic_version_is_reserved(0x1a2a3a4a) == 1);
  CHECK(quic_version_is_reserved(QUIC_VERSION_1) == 0);
  CHECK(quic_version_is_reserved(QUIC_VERSION_2) == 0);
}

static void test_version_info_roundtrip(void) {
  quic_version_info in = {.chosen = QUIC_VERSION_1, .n_available = 2};
  in.available[0]      = QUIC_VERSION_1;
  in.available[1]      = QUIC_VERSION_2;
  u8  buf[64];
  usz w = quic_version_info_encode(buf, sizeof(buf), &in);
  CHECK(w != 0 && buf[0] == QUIC_TP_VERSION_INFORMATION);

  quic_version_info out;
  usz               r = quic_version_info_decode(buf, w, &out);
  CHECK(r == w && out.chosen == QUIC_VERSION_1 && out.n_available == 2);
  CHECK(
      out.available[0] == QUIC_VERSION_1 && out.available[1] == QUIC_VERSION_2);
}

static void test_version_info_truncated(void) {
  quic_version_info in = {.chosen = QUIC_VERSION_2, .n_available = 1};
  in.available[0]      = QUIC_VERSION_2;
  u8                buf[64];
  usz               w = quic_version_info_encode(buf, sizeof(buf), &in);
  quic_version_info out;
  CHECK(quic_version_info_decode(buf, w - 1, &out) == 0);
}

void test_version(void) {
  test_version_reserved();
  test_version_info_roundtrip();
  test_version_info_truncated();
}
