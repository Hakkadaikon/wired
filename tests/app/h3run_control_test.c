#include "test.h"

/* RFC 9114 6.2.1: the control stream is prefixed by the type 0x00. */
static void test_control_open_prefix(void) {
  u8 buf[1] = {0xFF};
  CHECK(quic_h3run_control_open(buf, sizeof buf) == 1);
  CHECK(buf[0] == 0x00);
  CHECK(quic_h3run_control_open(buf, 0) == 0); /* no room */
}

/* RFC 9114 6.2.1: a second control stream is H3_STREAM_CREATION_ERROR. */
static void test_control_single(void) {
  quic_h3_control_state s = {0};
  CHECK(quic_h3_control_seen(&s) == 1);
  CHECK(quic_h3_control_seen(&s) == 0);
  CHECK(quic_h3_control_seen(&s) == 0);
}

void test_h3run_control(void) {
  test_control_open_prefix();
  test_control_single();
}
