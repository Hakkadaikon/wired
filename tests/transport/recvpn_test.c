#include "test.h"

/* Recording a packet number makes it seen; recording is idempotent. */
static void test_recvpn_dedup(void) {
  recvpn r;
  recvpn_init(&r);
  CHECK(recvpn_seen(&r, 5) == 0); /* nothing recorded yet */
  recvpn_record(&r, 5);
  CHECK(recvpn_seen(&r, 5) == 1);
  recvpn_record(&r, 5); /* idempotent */
  CHECK(recvpn_seen(&r, 5) == 1);

  recvpn_record(&r, 3); /* below largest */
  CHECK(recvpn_seen(&r, 3) == 1);
  CHECK(recvpn_seen(&r, 4) == 0); /* gap not recorded */
}

/* Numbers older than the window read as not-seen (already acknowledged). */
static void test_recvpn_window(void) {
  recvpn r;
  recvpn_init(&r);
  recvpn_record(&r, 100);
  CHECK(recvpn_seen(&r, 100 - RECVPN_WINDOW - 5) == 0);
  CHECK(recvpn_seen(&r, 200) == 0); /* newer than largest */
}

void test_recvpn(void) {
  test_recvpn_dedup();
  test_recvpn_window();
}
