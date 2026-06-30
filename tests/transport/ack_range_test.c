#include "test.h"

void test_ack_range(void) {
  /* first range within largest */
  CHECK(quic_ack_range_ok(10, 0) == 1);
  CHECK(quic_ack_range_ok(10, 10) == 1); /* down to packet 0 */
  CHECK(quic_ack_range_ok(10, 11) == 0); /* below zero */
  CHECK(quic_ack_range_ok(0, 0) == 1);
  CHECK(quic_ack_range_ok(0, 1) == 0);

  /* gap pair: smallest must be >= gap + range_len + 2 */
  CHECK(quic_ack_gap_ok(5, 0, 3) == 1); /* 5 >= 0+3+2 exactly */
  CHECK(quic_ack_gap_ok(4, 0, 3) == 0); /* 4 < 5, underflow */
  CHECK(quic_ack_gap_ok(2, 0, 0) == 1); /* 2 >= 2 exactly */
  CHECK(quic_ack_gap_ok(1, 0, 0) == 0); /* high would underflow */
  CHECK(quic_ack_gap_ok(0, 0, 0) == 0);

  /* large gap must not wrap below zero */
  CHECK(quic_ack_gap_ok(3, 5, 0) == 0);
  CHECK(quic_ack_gap_ok(100, 50, 48) == 1); /* 100 >= 50+48+2 */
  CHECK(quic_ack_gap_ok(100, 50, 49) == 0);
}
