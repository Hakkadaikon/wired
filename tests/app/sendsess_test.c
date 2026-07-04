#include "app/http3/server/sendsess/sendsess.h"

#include "test.h"

/* Taking slices in order and recording each send raises the in-flight
 * count; the queue drains front to back. */
static void test_sendsess_take_and_track(void) {
  u8                bytes[25];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 25, 10);
  CHECK(wired_sendsess_inflight(&s) == 0);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(sl.offset == 0 && sl.len == 10);
  CHECK(wired_sendsess_sent(&s, &sl, 5) == 1);
  CHECK(wired_sendsess_inflight(&s) == 1);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 6) == 1);
  CHECK(wired_sendsess_inflight(&s) == 2);
}

/* An ACK range consumes exactly the in-flight packets it covers; packet
 * numbers outside every logged entry change nothing. */
static void test_sendsess_ack_consumes(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 5);
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 6);
  wired_sendsess_ack(&s, 9, 12); /* unknown pns: no effect */
  CHECK(wired_sendsess_inflight(&s) == 2);
  wired_sendsess_ack(&s, 5, 5);
  CHECK(wired_sendsess_inflight(&s) == 1);
  wired_sendsess_ack(&s, 0, 20);
  CHECK(wired_sendsess_inflight(&s) == 0);
}

/* done fires only when everything was sent AND acknowledged, exactly once
 * (the session deactivates). */
static void test_sendsess_done_only_after_all_acked(void) {
  u8                bytes[15];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 15, 10);
  CHECK(wired_sendsess_done(&s) == 0); /* nothing sent yet */
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 0);
  CHECK(wired_sendsess_done(&s) == 0); /* tail unsent */
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 1);
  CHECK(wired_sendsess_done(&s) == 0); /* all sent, none acked */
  wired_sendsess_ack(&s, 0, 1);
  CHECK(wired_sendsess_done(&s) == 1);
  CHECK(wired_sendsess_done(&s) == 0); /* deactivated: fires once */
}

/* A requeued (lost) slice is retransmitted before any new slice. */
static void test_sendsess_requeue_first(void) {
  u8                bytes[30];
  wired_sendsess    s;
  wired_sendq_slice sl, lost;
  wired_sendsess_arm(&s, bytes, 30, 10);
  wired_sendsess_take(&s, &lost); /* offset 0 */
  s.requeue[s.requeue_n++] = lost;
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(sl.offset == 0); /* the requeued slice, not offset 10 */
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(sl.offset == 10); /* then the fresh tail */
}

void test_sendsess(void) {
  test_sendsess_take_and_track();
  test_sendsess_ack_consumes();
  test_sendsess_done_only_after_all_acked();
  test_sendsess_requeue_first();
}
