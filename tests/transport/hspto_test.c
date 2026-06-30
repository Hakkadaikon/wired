#include "test.h"

/* RFC 9002 6.2.2.1: handshake-space PTO excludes max_ack_delay until the
 * handshake is confirmed. */

static void test_hspto_excludes_ack_delay_before_confirm(void) {
  /* srtt=100, rttvar=10 -> max(40,1000)=1000; ack_delay 25 excluded. */
  CHECK(quic_hspto_duration(100, 10, 0, 1000, 0, 25) == 100 + 1000);
}

static void test_hspto_includes_ack_delay_after_confirm(void) {
  CHECK(quic_hspto_duration(100, 10, 0, 1000, 1, 25) == 100 + 1000 + 25);
}

static void test_hspto_uses_4rttvar_when_larger(void) {
  /* 4*rttvar=2000 > granularity 1000. */
  CHECK(quic_hspto_duration(100, 500, 0, 1000, 0, 25) == 100 + 2000);
}

static void test_hspto_backoff_count_zero(void) {
  CHECK(quic_hspto_duration(100, 10, 0, 1000, 1, 25) == (100 + 1000 + 25) * 1);
}

static void test_hspto_backoff_count_two(void) {
  CHECK(quic_hspto_duration(100, 10, 2, 1000, 1, 25) == (100 + 1000 + 25) * 4);
}

void test_hspto(void) {
  test_hspto_excludes_ack_delay_before_confirm();
  test_hspto_includes_ack_delay_after_confirm();
  test_hspto_uses_4rttvar_when_larger();
  test_hspto_backoff_count_zero();
  test_hspto_backoff_count_two();
}
