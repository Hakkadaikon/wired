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
    CHECK(wired_sendsess_detect_lost(&s, 4, 0, 0, lost, 4) == 2);
    /* the lost packet numbers are reported (for the caller's qlog) */
    CHECK((lost[0] == 0 && lost[1] == 1) || (lost[0] == 1 && lost[1] == 0));
  }
  CHECK(s.requeue_n == 2);
  CHECK(wired_sendsess_inflight(&s) == 2); /* pns 2,3 remain in flight */
  /* the lost slice retransmits (requeue first), never an acked one */
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(sl.offset == 10 || sl.offset == 0); /* one of the lost slices */
  /* below-threshold in-flight packets are untouched */
  CHECK(wired_sendsess_detect_lost(&s, 4, 0, 0, 0, 0) == 0);
  /* the largest acknowledged pn is tracked and never regresses */
  CHECK(s.has_acked == 1 && s.largest_acked == 4);
  wired_sendsess_ack(&s, 2, 2);
  CHECK(s.largest_acked == 4);
  wired_sendsess_arm(&s, bytes, 50, 10); /* re-arm resets the tracker */
  CHECK(s.has_acked == 0);
}

/* RFC 9002 6.1.2: the time threshold alone (independent of the packet
 * threshold) can also declare a slice lost -- the two criteria are an OR,
 * not a sequence. pn 4 is only 1 below largest_acked (well under
 * kPacketThreshold=3), so the packet threshold alone would leave it in
 * flight; a large elapsed time past 9/8*srtt must still declare it lost. */
static void test_sendsess_time_threshold_declares_lost_alone(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 4, 0) == 1); /* pn 4 sent at t=0ms */
  wired_sendsess_ack(&s, 5, 5); /* largest_acked=5: pn 4 is only 1 below */
  {
    u64 lost[1] = {99};
    /* srtt=1000us -> time threshold = 9/8*1000 = 1125us. at now_ms=2
     * (2000us elapsed), well past it; packet threshold alone (5-4=1 < 3)
     * would not have caught this. */
    CHECK(wired_sendsess_detect_lost(&s, 5, 2, 1000, lost, 1) == 1);
    CHECK(lost[0] == 4);
  }
  CHECK(s.requeue_n == 1);
  CHECK(wired_sendsess_inflight(&s) == 0);
}

/* REGRESSION (RFC 9002 6.1): "A packet is declared lost if ... it was sent
 * prior to an acknowledged packet. [...] The acknowledgment indicates that
 * a packet sent later was delivered" -- the time threshold in 6.1.2 is
 * subordinate to this premise, not an independent trigger. pn 4 has NOT
 * been superseded by any later-sent, now-acked packet (largest_acked stays
 * at its pre-arm value of 0, i.e. no ack ever named a pn > 4), so even a
 * huge elapsed time must NOT declare it lost -- only "it's been sitting
 * around a while" with nothing newer proven delivered. A real burst-send
 * scenario hit exactly this: several packets sent in the same step (same
 * sent_ms) got declared lost the instant elapsed time alone crossed
 * 9/8*RTT, with nothing after them ever acknowledged yet. */
static void test_sendsess_time_threshold_requires_later_ack(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 4, 0) == 1); /* pn 4 sent at t=0ms */
  /* no ack at all yet: largest_acked passed in is 0, e->pn(4) >= 0 */
  CHECK(wired_sendsess_detect_lost(&s, 0, 100000, 1000, 0, 0) == 0);
  CHECK(wired_sendsess_inflight(&s) == 1);
}

/* REGRESSION (RFC 9002 6.1.1's own "sent prior to an acknowledged packet"
 * premise): largest_acked == pn (nothing sent AFTER pn has been
 * acknowledged, an ack for pn itself doesn't count) must not declare pn
 * lost via the packet threshold, however large kPacketThreshold's own
 * arithmetic might otherwise read on unsigned wraparound. Explicit
 * boundary check for sendsess_lost_eligible's pn < largest_acked cut. */
static void test_sendsess_packet_threshold_requires_later_ack(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 4, 0) == 1);
  /* largest_acked == pn: not "sent prior to an acknowledged packet" */
  CHECK(wired_sendsess_detect_lost(&s, 4, 0, 0, 0, 0) == 0);
  CHECK(wired_sendsess_inflight(&s) == 1);
}

/* srtt_us == 0 (no RTT sample yet) must not spuriously satisfy the time
 * threshold -- quic_loss_by_time's elapsed>=threshold could otherwise fire
 * on any elapsed time with threshold computed from a zero RTT. Same setup
 * as above but srtt_us=0: pn 4 must stay in flight. */
static void test_sendsess_time_threshold_skipped_without_rtt_sample(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 4, 0) == 1);
  wired_sendsess_ack(&s, 5, 5);
  CHECK(wired_sendsess_detect_lost(&s, 5, 2, 0, 0, 0) == 0);
  CHECK(wired_sendsess_inflight(&s) == 1);
}

/* wired_sendsess_oldest_sent_ms reports the oldest in-flight slice's send
 * time -- what a caller compares against an RTT-derived PTO deadline before
 * ever calling wired_sendsess_pto_fire, so a session isn't probed before
 * its PTO window has actually elapsed. Nothing in flight (never armed, or
 * fully acked) reports 0/no-op. */
static void test_sendsess_oldest_sent_ms(void) {
  u8                bytes[30];
  wired_sendsess    s;
  wired_sendq_slice sl;
  u64               out = 999;
  wired_sendsess_arm(&s, bytes, 30, 10);
  CHECK(wired_sendsess_oldest_sent_ms(&s, &out) == 0); /* nothing sent yet */
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 0, 1000) == 1);
  CHECK(wired_sendsess_take(&s, &sl) == 1);
  CHECK(wired_sendsess_sent(&s, &sl, 1, 1500) == 1);
  CHECK(wired_sendsess_oldest_sent_ms(&s, &out) == 1);
  CHECK(out == 1000);           /* the earlier of the two in-flight sends */
  wired_sendsess_ack(&s, 0, 0); /* the oldest slice is acked... */
  CHECK(wired_sendsess_oldest_sent_ms(&s, &out) == 1);
  CHECK(out == 1500); /* ...so the remaining slice is now the oldest */
  wired_sendsess_ack(&s, 1, 1); /* nothing in flight anymore */
  CHECK(wired_sendsess_oldest_sent_ms(&s, &out) == 0);
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

/* A fresh arm starts at stream base offset 0 (the common, non-streaming
 * case): the absolute offset helper matches the slice's own offset. */
static void test_sendsess_stream_offset_defaults_to_zero(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  wired_sendsess_take(&s, &sl);
  CHECK(wired_sendsess_stream_offset(&s, &sl) == 0);
}

/* wired_sendsess_set_base_offset shifts every subsequent slice's absolute
 * stream offset by the given amount, without touching the slice's own
 * (round-local) offset -- this is how a re-armed round N+1 continues the
 * QUIC stream's absolute byte numbering instead of restarting at 0
 * (T-018: streaming rounds must not rewind the stream offset). */
static void test_sendsess_stream_offset_after_base_set(void) {
  u8                bytes[20];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 20, 10);
  wired_sendsess_set_base_offset(&s, 640 * 1024);
  wired_sendsess_take(&s, &sl);
  CHECK(sl.offset == 0); /* round-local offset is unchanged */
  CHECK(wired_sendsess_stream_offset(&s, &sl) == 640 * 1024);
  wired_sendsess_take(&s, &sl);
  CHECK(sl.offset == 10);
  CHECK(wired_sendsess_stream_offset(&s, &sl) == 640 * 1024 + 10);
}

/* Re-arming for the next round resets active/log/requeue state AND the base
 * offset back to 0 (a fresh arm always starts a session from scratch) -- a
 * streaming round driver must call set_base_offset again after every arm
 * with the cumulative bytes sent so far (T-019: no accidental double count
 * or silent reset losing the accumulated offset). */
static void test_sendsess_stream_offset_explicit_each_round(void) {
  u8                bytes[10];
  wired_sendsess    s;
  wired_sendq_slice sl;
  wired_sendsess_arm(&s, bytes, 10, 10);
  wired_sendsess_set_base_offset(&s, 100);
  wired_sendsess_take(&s, &sl);
  CHECK(wired_sendsess_stream_offset(&s, &sl) == 100);
  /* round 2: re-arm over a fresh buffer, explicitly advance the base by
   * exactly what round 1 sent (100 + 10 == 110) -- no gap, no overlap. */
  wired_sendsess_arm(&s, bytes, 10, 10);
  wired_sendsess_set_base_offset(&s, 110);
  wired_sendsess_take(&s, &sl);
  CHECK(wired_sendsess_stream_offset(&s, &sl) == 110);
}

/* BOUNDARY: once the log holds WIRED_SENDSESS_LOG in-flight entries, one
 * more wired_sendsess_sent must fail (0) and leave in-flight unchanged --
 * the exact condition srvrun_send_stream_slice hits when cwnd outgrows the
 * log (see WIRED_SENDSESS_LOG's own doc comment for why a full log silently
 * drops already-wire-sent packets from tracking rather than refusing to
 * send them). */
static void test_sendsess_log_full_rejects_one_more(void) {
  u8                bytes[(WIRED_SENDSESS_LOG + 1) * 10];
  wired_sendsess    s;
  wired_sendq_slice sl;
  usz               i;
  wired_sendsess_arm(&s, bytes, sizeof bytes, 10);
  for (i = 0; i < WIRED_SENDSESS_LOG; i++) {
    CHECK(wired_sendsess_take(&s, &sl) == 1);
    CHECK(wired_sendsess_sent(&s, &sl, i, 0) == 1);
  }
  CHECK(wired_sendsess_inflight(&s) == WIRED_SENDSESS_LOG);
  CHECK(wired_sendsess_take(&s, &sl) == 1); /* queue still has more to take */
  CHECK(
      wired_sendsess_sent(&s, &sl, WIRED_SENDSESS_LOG, 0) == 0); /* log full */
  CHECK(wired_sendsess_inflight(&s) == WIRED_SENDSESS_LOG);      /* unchanged */
}

/* T-002: the log's real capacity is exactly WIRED_SENDSESS_LOG -- every one
 * of those slots is fillable (regression guard against the constant and
 * the array bound silently drifting apart). */
static void test_sendsess_log_capacity_matches_constant(void) {
  u8                bytes[WIRED_SENDSESS_LOG * 10];
  wired_sendsess    s;
  wired_sendq_slice sl;
  usz               i;
  wired_sendsess_arm(&s, bytes, sizeof bytes, 10);
  for (i = 0; i < WIRED_SENDSESS_LOG; i++) {
    CHECK(wired_sendsess_take(&s, &sl) == 1);
    CHECK(wired_sendsess_sent(&s, &sl, i, 0) == 1);
  }
  CHECK(wired_sendsess_inflight(&s) == WIRED_SENDSESS_LOG);
}

/* T-003: past the OLD 32-slice cap (the goodput interop regression's exact
 * trigger point), in-flight bytes must keep accumulating instead of silently
 * losing track of newly sent slices -- proves the log now has headroom past
 * where the bug used to bite. 35 slices * 10 bytes = 350, comfortably past
 * the old 32-entry ceiling. */
static void test_sendsess_inflight_bytes_survive_past_old_cap(void) {
  u8                bytes[350];
  wired_sendsess    s;
  wired_sendq_slice sl;
  usz               i;
  wired_sendsess_arm(&s, bytes, sizeof bytes, 10);
  for (i = 0; i < 35; i++) {
    CHECK(wired_sendsess_take(&s, &sl) == 1);
    CHECK(wired_sendsess_sent(&s, &sl, i, 0) == 1);
  }
  CHECK(wired_sendsess_inflight_bytes(&s) == 350);
}

void test_sendsess(void) {
  test_sendsess_take_and_track();
  test_sendsess_ack_consumes();
  test_sendsess_done_only_after_all_acked();
  test_sendsess_requeue_first();
  test_sendsess_threshold_declares_lost();
  test_sendsess_time_threshold_declares_lost_alone();
  test_sendsess_time_threshold_requires_later_ack();
  test_sendsess_packet_threshold_requires_later_ack();
  test_sendsess_time_threshold_skipped_without_rtt_sample();
  test_sendsess_oldest_sent_ms();
  test_sendsess_pto_probes_oldest();
  test_sendsess_pto_resets_on_ack();
  test_sendsess_pto_exhaustion_fails();
  test_sendsess_peek_ack_bytes();
  test_sendsess_stream_offset_defaults_to_zero();
  test_sendsess_stream_offset_after_base_set();
  test_sendsess_stream_offset_explicit_each_round();
  test_sendsess_log_full_rejects_one_more();
  test_sendsess_log_capacity_matches_constant();
  test_sendsess_inflight_bytes_survive_past_old_cap();
}
