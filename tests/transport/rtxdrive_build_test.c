#include "test.h"

/* RFC 9002 13.3: store -> loss -> build recovers the original frame bytes
 * verbatim (the real-bytes replacement for a PING stand-in). */
static void test_build_roundtrip(void) {
  quic_rtxbytes st;
  const u8      s1[] = {0x08, 0x04, 0x03, 'b', 'y', 'e'};
  u8            out[64];
  usz           out_len = 0;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 7, s1, sizeof s1);

  CHECK(quic_rtxdrive_build(&st, 7, out, sizeof out, &out_len) == 1);
  CHECK(out_len == sizeof s1);
  for (usz i = 0; i < sizeof s1; i++) CHECK(out[i] == s1[i]);
}

static void test_build_ack_skipped(void) {
  quic_rtxbytes st;
  const u8      ack[] = {0x02, 0x00, 0x00, 0x00};
  u8            out[64];
  usz           out_len = 99;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 8, ack, sizeof ack);

  CHECK(quic_rtxdrive_build(&st, 8, out, sizeof out, &out_len) == 1);
  CHECK(out_len == 0);
}

static void test_build_pn_not_held(void) {
  quic_rtxbytes st;
  u8            out[64];
  usz           out_len = 99;

  quic_rtxbytes_init(&st);
  CHECK(quic_rtxdrive_build(&st, 5, out, sizeof out, &out_len) == 1);
  CHECK(out_len == 0);
}

static void test_build_no_room(void) {
  quic_rtxbytes st;
  const u8      s1[] = {0x08, 0x00, 0x02, 'h', 'i'};
  u8            out[2];
  usz           out_len = 0;

  quic_rtxbytes_init(&st);
  quic_rtxbytes_store(&st, 3, s1, sizeof s1);
  CHECK(quic_rtxdrive_build(&st, 3, out, sizeof out, &out_len) == 0);
}

void test_rtxdrive_build(void) {
  test_build_roundtrip();
  test_build_ack_skipped();
  test_build_pn_not_held();
  test_build_no_room();
}
