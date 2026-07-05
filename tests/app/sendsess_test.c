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
  CHECK(wired_sendsess_sent(&s, &sl, 5, 0) == 1);
  CHECK(wired_sendsess_inflight(&s) == 1);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 6, 0) == 1);
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
  wired_sendsess_sent(&s, &sl, 5, 0);
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 6, 0);
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
  wired_sendsess_sent(&s, &sl, 0, 0);
  CHECK(wired_sendsess_done(&s) == 0); /* tail unsent */
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 1, 0);
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

/* Packets at least 3 below the largest acknowledged that are still in
 * flight are declared lost and moved to the requeue (RFC 9002 6.1.1); the
 * requeued slice goes out again while acknowledged ones never do. */
static void test_sendsess_threshold_declares_lost(void) {
  u8                bytes[50];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 50, 10);
  for (u64 pn = 0; pn < 5; pn++) { /* pns 0..4 in flight */
    CHECK(wired_sendsess_take(&s, &sl) == 1);
    CHECK(wired_sendsess_sent(&s, &sl, pn, 0) == 1);
  }
  wired_sendsess_ack(&s, 4, 4); /* largest acked 4: pns 0,1 are <= 4-3 */
  {
    u64 lost[4] = {99, 99, 99, 99};
    CHECK(wired_sendsess_detect_lost(&s, 4, lost, 4) == 2);
    /* the lost packet numbers are reported (for the caller's qlog) */
    CHECK((lost[0] == 0 && lost[1] == 1) || (lost[0] == 1 && lost[1] == 0));
  }
  CHECK(s.requeue_n == 2);
  CHECK(wired_sendsess_inflight(&s) == 2); /* pns 2,3 remain in flight */
  /* the lost slice retransmits (requeue first), never an acked one */
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(sl.offset == 10 || sl.offset == 0); /* one of the lost slices */
  /* below-threshold in-flight packets are untouched */
  CHECK(wired_sendsess_detect_lost(&s, 4, 0, 0) == 0);
  /* the largest acknowledged pn is tracked and never regresses */
  CHECK(s.has_acked == 1 && s.largest_acked == 4);
  wired_sendsess_ack(&s, 2, 2);
  CHECK(s.largest_acked == 4);
  wired_sendsess_arm(&s, bytes, 50, 10); /* re-arm resets the tracker */
  CHECK(s.has_acked == 0);
}

/* A PTO probe requeues the oldest in-flight slice (smallest pn) so it goes
 * out again with a fresh packet number; younger packets stay in flight. */
static void test_sendsess_pto_probes_oldest(void) {
  u8                bytes[30];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 30, 10);
  for (u64 pn = 0; pn < 3; pn++) {
    CHECK(wired_sendsess_take(&s, &sl) == 1);
    CHECK(wired_sendsess_sent(&s, &sl, pn + 7, 0) == 1);
  }
  CHECK(wired_sendsess_pto_fire(&s, 5) == 1);
  CHECK(s.requeue_n == 1);
  CHECK(s.requeue[0].offset == 0); /* pn 7 carried offset 0: the oldest */
  CHECK(wired_sendsess_inflight(&s) == 2);
  CHECK(s.pto_count == 1);
}

/* An arriving ACK resets the PTO backoff counter. */
static void test_sendsess_pto_resets_on_ack(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 0, 0);
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 1, 0);
  CHECK(wired_sendsess_pto_fire(&s, 5) == 1);
  CHECK(wired_sendsess_pto_fire(&s, 5) == 1);
  CHECK(s.pto_count == 2);
  wired_sendsess_ack(&s, 0, 0);
  CHECK(s.pto_count == 0);
}

/* Exhausting the PTO budget reports failure (the caller tears the
 * connection down); with nothing in flight a fire is a harmless no-op. */
static void test_sendsess_pto_exhaustion_fails(void) {
  u8                bytes[10];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 10, 10);
  CHECK(wired_sendsess_pto_fire(&s, 2) == 1); /* nothing in flight: no-op */
  CHECK(s.pto_count == 0);
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 0, 0);
  CHECK(wired_sendsess_pto_fire(&s, 2) == 1); /* probe 1 */
  wired_sendsess_take(&s, &sl);               /* re-send the probe */
  wired_sendsess_sent(&s, &sl, 1, 0);
  CHECK(wired_sendsess_pto_fire(&s, 2) == 1); /* probe 2 */
  wired_sendsess_take(&s, &sl);
  wired_sendsess_sent(&s, &sl, 2, 0);
  CHECK(wired_sendsess_pto_fire(&s, 2) == 0); /* budget spent: failed */
}

/* peek_ack reports the bytes and newest send time an ACK range would
 * consume, without consuming it; inflight_bytes sums in-flight lens. */
static void test_sendsess_peek_ack_bytes(void) {
  u8                bytes[25];
  wired_sendsess    s;
  wired_sendq_slice sl;
  u64               newest = 0;
  wired_sendsess_arm(&s, bytes, 25, 10);
  wired_sendsess_take(&s, &sl);
  CHECK(wired_sendsess_sent(&s, &sl, 0, 100) == 1); /* 10 bytes, t=100 */
  wired_sendsess_take(&s, &sl);
  CHECK(wired_sendsess_sent(&s, &sl, 1, 200) == 1); /* 10 bytes, t=200 */
  wired_sendsess_take(&s, &sl);
  CHECK(wired_sendsess_sent(&s, &sl, 2, 300) == 1); /* 5 bytes, t=300 */
  CHECK(wired_sendsess_inflight_bytes(&s) == 25);
  CHECK(wired_sendsess_peek_ack(&s, 0, 1, &newest) == 20);
  CHECK(newest == 200);
  CHECK(wired_sendsess_peek_ack(&s, 7, 9, &newest) == 0); /* unknown pns */
  /* peek does not consume: everything still in flight */
  CHECK(wired_sendsess_inflight(&s) == 3);
  wired_sendsess_ack(&s, 0, 1);
  CHECK(wired_sendsess_inflight_bytes(&s) == 5);
}

void test_sendsess(void) {
  test_sendsess_take_and_track();
  test_sendsess_ack_consumes();
  test_sendsess_done_only_after_all_acked();
  test_sendsess_requeue_first();
  test_sendsess_threshold_declares_lost();
  test_sendsess_pto_probes_oldest();
  test_sendsess_pto_resets_on_ack();
  test_sendsess_pto_exhaustion_fails();
  test_sendsess_peek_ack_bytes();
}
