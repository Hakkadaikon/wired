#include "test.h"

/* Recording a packet number makes it seen; recording is idempotent. */
static void test_recvpn_dedup(void) {
  quic_recvpn r;
  quic_recvpn_init(&r);
  CHECK(quic_recvpn_seen(&r, 5) == 0); /* nothing recorded yet */
  quic_recvpn_record(&r, 5);
  CHECK(quic_recvpn_seen(&r, 5) == 1);
  quic_recvpn_record(&r, 5); /* idempotent */
  CHECK(quic_recvpn_seen(&r, 5) == 1);

  quic_recvpn_record(&r, 3); /* below largest */
  CHECK(quic_recvpn_seen(&r, 3) == 1);
  CHECK(quic_recvpn_seen(&r, 4) == 0); /* gap not recorded */
}

/* Numbers older than the window read as not-seen (already acknowledged). */
static void test_recvpn_window(void) {
  quic_recvpn r;
  quic_recvpn_init(&r);
  quic_recvpn_record(&r, 100);
  CHECK(quic_recvpn_seen(&r, 100 - QUIC_RECVPN_WINDOW - 5) == 0);
  CHECK(quic_recvpn_seen(&r, 200) == 0); /* newer than largest */
}

/* The first ACK range counts contiguous packets ending at largest. */
static void test_recvpn_first_range(void) {
  quic_recvpn r;
  quic_recvpn_init(&r);
  quic_recvpn_record(&r, 10);
  CHECK(quic_recvpn_first_range(&r) == 0); /* only largest, no run below */

  quic_recvpn_record(&r, 9);
  quic_recvpn_record(&r, 8);
  CHECK(quic_recvpn_first_range(&r) == 2); /* 9 and 8 contiguous below 10 */

  quic_recvpn_record(&r, 6);               /* gap at 7 */
  CHECK(quic_recvpn_first_range(&r) == 2); /* run still stops at 8 */
}

void test_recvpn(void) {
  test_recvpn_dedup();
  test_recvpn_window();
  test_recvpn_first_range();
}
