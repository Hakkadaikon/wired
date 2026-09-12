#include "transport/recovery/congestion/cc/ecn.h"

int ecn_ce_increased(u64 prev_ce, u64 new_ce) { return new_ce > prev_ce; }

int ecn_counts_valid(ecn_counts prev, ecn_counts next) {
  return next.ce >= prev.ce && next.ect0 >= prev.ect0;
}

void ecn_on_ce_increase(
    cc* c, u64 prev_ce, u64 new_ce, u64 sent_time, u64 now) {
  if (!ecn_ce_increased(prev_ce, new_ce)) return;
  cc_on_loss(c, sent_time, now);
}

void ecn_track_init(ecn_track* t) {
  t->enabled    = 1;
  t->prev.ce    = 0;
  t->prev.ect0  = 0;
  t->fail_count = 0;
}

/* Record one validation failure and stop consuming ECN feedback
 * (RFC 9000 13.4.2.2). */
static void ecn_track_fail(ecn_track* t) {
  t->enabled = 0;
  t->fail_count++;
}

/* RFC 9000 13.4.2.1, on a report already known not to regress: the total
 * never exceeds packets sent, and ECT(0)+CE rose by at least the packets
 * newly acked (it may rise by more -- earlier ACK frames can be lost). */
static int ecn_report_bounded(
    ecn_counts prev, ecn_counts next, u64 sent_ect, u64 newly_acked) {
  return next.ect0 + next.ce <= sent_ect &&
         (next.ect0 - prev.ect0) + (next.ce - prev.ce) >= newly_acked;
}

/* 1 when the report is consistent: counts never decrease, no ECT(1) (we
 * only ever mark ECT(0)), and the totals are bounded as above. */
static int ecn_report_ok(
    const ecn_track* t, ecn_counts next, u64 ect1, u64 sent_ect, u64 newly) {
  return ecn_counts_valid(t->prev, next) && ect1 == 0 &&
         ecn_report_bounded(t->prev, next, sent_ect, newly);
}

void ecn_track_on_counts(
    ecn_track* t,
    cc*        c,
    ecn_counts next,
    u64        ect1,
    u64        sent_ect,
    u64        newly_acked,
    u64        sent_time,
    u64        now) {
  if (!t->enabled) return;
  if (!ecn_report_ok(t, next, ect1, sent_ect, newly_acked)) {
    ecn_track_fail(t);
    return;
  }
  ecn_on_ce_increase(c, t->prev.ce, next.ce, sent_time, now);
  t->prev = next;
}

void ecn_track_on_missing(ecn_track* t, u64 sent_ect) {
  if (t->enabled && sent_ect > 0) ecn_track_fail(t);
}
