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
    u8        buf[32];
    u64       id, val;
    quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
    usz       w  = quic_tparam_put_int(&ob, cases[i].id, cases[i].val);
    usz       r  = quic_tparam_get_int(quic_span_of(buf, w), &id, &val);
    CHECK(w != 0 && r == w && id == cases[i].id && val == cases[i].val);
  }
}

static void test_tparam_truncated(void) {
  u8        buf[32];
  u64       id, val;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  usz       w  = quic_tparam_put_int(&ob, QUIC_TP_INITIAL_MAX_DATA, 1048576);
  /* feeding fewer bytes than encoded must fail */
  CHECK(quic_tparam_get_int(quic_span_of(buf, w - 1), &id, &val) == 0);
  /* no room to encode */
  quic_obuf tiny = quic_obuf_of(buf, 1);
  CHECK(quic_tparam_put_int(&tiny, QUIC_TP_INITIAL_MAX_DATA, 1048576) == 0);
}

/* RFC 9221 3: max_datagram_frame_size is encoded/decoded as a plain single
 * varint via the same generic codec as every other integer TP. 65535 is the
 * RECOMMENDED value (needs the 4-byte varint form); 16383 is the largest
 * 2-byte varint, a boundary of the underlying varint codec; 0 is a valid
 * varint to round-trip even though callers interpret it as "unsupported". */
static void test_tparam_max_datagram_frame_size(void) {
  u64 cases[] = {65535, 16383, 0};
  for (usz i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    u8        buf[32];
    u64       id, val;
    quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
    usz       w =
        quic_tparam_put_int(&ob, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, cases[i]);
    usz r = quic_tparam_get_int(quic_span_of(buf, w), &id, &val);
    CHECK(
        w != 0 && r == w && id == QUIC_TP_MAX_DATAGRAM_FRAME_SIZE &&
        val == cases[i]);
  }
}

void test_tparam(void) {
  test_tparam_roundtrip();
  test_tparam_truncated();
  test_tparam_max_datagram_frame_size();
}
