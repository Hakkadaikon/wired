#include "test.h"

static void test_tparam_roundtrip(void) {
  struct {
    u64 id, val;
  } cases[] = {
      {QUIC_TP_MAX_IDLE_TIMEOUT, 30000},
      {QUIC_TP_INITIAL_MAX_DATA, 1048576},
      {QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 100},
      {QUIC_TP_MAX_UDP_PAYLOAD_SIZE, 1200},
  };
  for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    u8  buf[32];
    u64 id, val;
    usz w = quic_tparam_put_int(buf, sizeof(buf), cases[i].id, cases[i].val);
    usz r = quic_tparam_get_int(buf, w, &id, &val);
    CHECK(w != 0 && r == w && id == cases[i].id && val == cases[i].val);
  }
}

static void test_tparam_truncated(void) {
  u8  buf[32];
  u64 id, val;
  usz w =
      quic_tparam_put_int(buf, sizeof(buf), QUIC_TP_INITIAL_MAX_DATA, 1048576);
  /* feeding fewer bytes than encoded must fail */
  CHECK(quic_tparam_get_int(buf, w - 1, &id, &val) == 0);
  /* no room to encode */
  CHECK(quic_tparam_put_int(buf, 1, QUIC_TP_INITIAL_MAX_DATA, 1048576) == 0);
}

void test_tparam(void) {
  test_tparam_roundtrip();
  test_tparam_truncated();
}
