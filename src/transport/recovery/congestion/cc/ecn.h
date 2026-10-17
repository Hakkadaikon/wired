#ifndef CC_ECN_H
#define CC_ECN_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/congestion/cc/cc.h"

/* RFC 9002 7.1.2: ECN counts must increase monotonically; a CE increase
 * signals congestion. Counts are cumulative per-path. */

/** Cumulative ECN counts (CE and ECT(0)) at one point in time. */
typedef struct {
  u64 ce;
  u64 ect0;
} ecn_counts;

/* 1 if both CE and ECT(0) counts did not decrease, else 0. */
int ecn_counts_valid(ecn_counts prev, ecn_counts next);

/* 1 if the CE count increased. */
int ecn_ce_increased(u64 prev_ce, u64 new_ce);

/* RFC 9002 7.1.2: "An increase in the CE count is treated as one instance of
 * congestion detection and is handled as if the endpoint had detected a
 * packet loss" -- when the CE count rose since prev_ce, apply the same
 * window reduction cc_on_loss uses (never twice for one recovery
 * period, same in_recovery/recovery_start gating as an ordinary loss). A
 * no-op when the CE count did not increase. */
void ecn_on_ce_increase(cc* c, u64 prev_ce, u64 new_ce, u64 sent_time, u64 now);

/** Per-connection ECN validation state (RFC 9000 13.4.2): whether the
 * peer's ECN feedback is still trusted, the cumulative counts last
 * accepted from it, and how many validation failures were observed. */
typedef struct {
  /** 1 while ECN feedback is consumed; 0 once validation failed. */
  u8 enabled;
  /** Cumulative counts last accepted from the peer (RFC 9000 19.3.2). */
  ecn_counts prev;
  /** Validation failures observed (RFC 9000 13.4.2.2), a stat counter. */
  u64 fail_count;
} ecn_track;

/* Start trusting ECN feedback with zero accepted counts. */
void ecn_track_init(ecn_track* t);

/** One ACK frame's ECN report and what our side knows about it. */
typedef struct {
  /** The ACK's cumulative CE and ECT(0) counts. */
  ecn_counts next;
  /** The ACK's ECT(1) count. */
  u64 ect1;
  /** ECT(0)-marked packets we have sent so far on the path. */
  u64 sent_ect;
  /** How many of those this ACK newly acknowledged. */
  u64 newly_acked;
} ecn_report;

/* Feed one received ACK frame's ECN report r (see ecn_report). A report that
 * regresses, exceeds sent_ect, claims ECT(1) we never mark, or raises ECT(0)+CE
 * by less than newly_acked (a suppressed report, RFC 9000 13.4.2.1) fails
 * validation (13.4.2.2): ECN is disabled and cc is untouched. A valid report's
 * CE increase becomes one congestion event (ecn_on_ce_increase). Only call for
 * an ACK that raised the largest acknowledged packet number (13.4.2.1 MUST NOT
 * fail on a reordered one). */
void ecn_track_on_counts(
    ecn_track* t, cc* c, const ecn_report* r, u64 sent_time, u64 now);

/* Feed an ACK that acknowledged packets but carried no ECN counts. Once
 * any ECT(0) packet was sent (sent_ect > 0) that means the peer or path
 * dropped the marks: validation fails (RFC 9000 13.4.2.1). */
void ecn_track_on_missing(ecn_track* t, u64 sent_ect);

#endif
