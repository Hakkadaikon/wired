#include "app/http3/server/sendsess/sendsess_impl.h"

static int sendsess_lost_by_packet(
    const wired_sent_slice* e, u64 largest_acked);
static int sendsess_lost_by_time(
    const wired_sent_slice* e, u64 now_ms, u64 loss_delay_us);
static int sendsess_lost_eligible(const wired_sent_slice* e, u64 largest_acked);
static int sendsess_lost(
    const wired_sent_slice* e,
    u64                     largest_acked,
    u64                     now_ms,
    u64                     loss_delay_us);
static void sendsess_requeue(wired_sendsess* s, usz i);
static void sendsess_report_lost(
    const wired_sendsess*      s,
    const wired_sent_slice*    e,
    wired_sendsess_lost_slice* lost,
    usz                        cap,
    usz                        i);
static int sendsess_older(const wired_sendsess* s, int best, usz i);
static int sendsess_oldest(const wired_sendsess* s);
static int sendsess_requeue_oldest(wired_sendsess* s);
static usz sendsess_live_min(usz off, int live, usz base);
static usz sendsess_log_min_off(const wired_sendsess* s, usz base);
static usz sendsess_requeue_min_off(const wired_sendsess* s, usz base);
static int sendsess_pending(const wired_sendsess* s);

/* RFC 9002 6.1.1: 1 if in-flight entry e is past the packet threshold. */
static int sendsess_lost_by_packet(
    const wired_sent_slice* e, u64 largest_acked) {
  return loss_by_packet(largest_acked, e->pn);
}

/* RFC 9002 6.1.2 / A.10: 1 if in-flight entry e was sent at or before
 * now - loss_delay (the caller's max(kTimeThreshold * max(smoothed_rtt,
 * latest_rtt), kGranularity), lossdrive_loss_delay). loss_delay_us == 0 (no
 * RTT sample yet) always reads not-lost -- the packet threshold alone still
 * applies via sendsess_lost. */
static int sendsess_lost_by_time(
    const wired_sent_slice* e, u64 now_ms, u64 loss_delay_us) {
  return loss_delay_us && e->sent_ms * 1000 + loss_delay_us <= now_ms * 1000;
}

/* RFC 9002 6.1: "A packet is declared lost if it meets all of the following
 * conditions: The packet is unacknowledged, in flight, and was sent prior
 * to an acknowledged packet. [...] The acknowledgment indicates that a
 * packet sent later was delivered" -- a packet can only be DECLARED lost
 * once some packet sent AFTER it has already been acknowledged; e->pn <
 * largest_acked is that prerequisite, required before EITHER the packet or
 * time threshold below applies. Without it, a burst of packets sent in one
 * step (their sent_ms all equal) trips the time threshold the moment
 * elapsed time alone exceeds 9/8*RTT, even though none of them are
 * actually behind an ACK yet (RFC 9002 6.1.2's own text ties the time
 * threshold to the same "sent prior to an acknowledged packet" premise as
 * 6.1.1, it does not stand alone). */
static int sendsess_lost_eligible(
    const wired_sent_slice* e, u64 largest_acked) {
  return e->inflight && e->pn < largest_acked;
}

static int sendsess_lost(
    const wired_sent_slice* e,
    u64                     largest_acked,
    u64                     now_ms,
    u64                     loss_delay_us) {
  if (!sendsess_lost_eligible(e, largest_acked)) {
    return 0;
  }
  return sendsess_lost_by_packet(e, largest_acked) ||
         sendsess_lost_by_time(e, now_ms, loss_delay_us);
}

/* Move log entry i's slice to the requeue (dropped silently if full — the
 * next detect pass picks it up again since the entry stays in flight). */
static void sendsess_requeue(wired_sendsess* s, usz i) {
  if (s->requeue_n >= WIRED_SENDSESS_LOG) {
    return;
  }
  s->requeue[s->requeue_n++] = s->log[i].sl;
  s->log[i].inflight         = 0;
}

/* Report one lost slice to the caller's array (skipped without one). */
static void sendsess_report_lost(
    const wired_sendsess*      s,
    const wired_sent_slice*    e,
    wired_sendsess_lost_slice* lost,
    usz                        cap,
    usz                        i) {
  if (!lost || i >= cap) {
    return;
  }
  lost[i] = (wired_sendsess_lost_slice){
      e->pn, wired_sendsess_stream_offset(s, &e->sl), e->sl.len, e->sl.fin,
      e->sent_ms};
}

usz wired_sendsess_detect_lost(
    wired_sendsess*            s,
    u64                        largest_acked,
    u64                        now_ms,
    u64                        loss_delay_us,
    wired_sendsess_lost_slice* lost,
    usz                        cap) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    if (sendsess_lost(&s->log[i], largest_acked, now_ms, loss_delay_us)) {
      sendsess_report_lost(s, &s->log[i], lost, cap, n);
      sendsess_requeue(s, i);
      n++;
    }
  }
  return n;
}

/* 1 if log[i] is in flight and older (smaller pn) than log[best]. */
static int sendsess_older(const wired_sendsess* s, int best, usz i) {
  return s->log[i].inflight &&
         (best < 0 || s->log[i].pn < s->log[(usz)best].pn);
}

/* Index of the oldest in-flight entry, -1 when none is. */
static int sendsess_oldest(const wired_sendsess* s) {
  int best = -1;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    if (sendsess_older(s, best, i)) {
      best = (int)i;
    }
  }
  return best;
}

int wired_sendsess_oldest_sent_ms(const wired_sendsess* s, u64* out) {
  int i = sendsess_oldest(s);
  if (i < 0) {
    return 0;
  }
  *out = s->log[(usz)i].sent_ms;
  return 1;
}

/* Requeue the oldest in-flight slice; 1 if one existed. A full requeue
 * array drops the slice (sendsess_requeue's own cap) and it simply stays
 * in flight for a later pass. */
static int sendsess_requeue_oldest(wired_sendsess* s) {
  int i = sendsess_oldest(s);
  if (i < 0) {
    return 0;
  }
  sendsess_requeue(s, (usz)i);
  return 1;
}

int wired_sendsess_pto_fire(wired_sendsess* s, int max) {
  if (sendsess_oldest(s) < 0) {
    return 1;
  }
  if (s->pto_count >= max) {
    return 0;
  }
  s->pto_count++;
  /* RFC 9002 6.2.4: a PTO probe may carry up to two datagrams -- requeue
   * the two oldest slices so a fully lost tail recovers in parallel
   * instead of one slice per backoff round. */
  sendsess_requeue_oldest(s);
  sendsess_requeue_oldest(s);
  return 1;
}

/* off if it is live (a candidate the retransmit path may still read) and
 * lower than the running minimum, else the minimum unchanged. */
static usz sendsess_live_min(usz off, int live, usz base) {
  return live && off < base ? off : base;
}

/* Fold the in-flight log's offsets into the running minimum. */
static usz sendsess_log_min_off(const wired_sendsess* s, usz base) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    base = sendsess_live_min(s->log[i].sl.offset, s->log[i].inflight, base);
  }
  return base;
}

/* Fold the requeue's offsets into the running minimum. */
static usz sendsess_requeue_min_off(const wired_sendsess* s, usz base) {
  for (usz i = 0; i < s->requeue_n; i++) {
    base = sendsess_live_min(s->requeue[i].offset, 1, base);
  }
  return base;
}

usz wired_sendsess_reclaim_base(const wired_sendsess* s) {
  return sendsess_requeue_min_off(s, sendsess_log_min_off(s, s->q.cur));
}

usz wired_sendsess_ring_room(const wired_sendsess* s, usz cap) {
  return cap - (s->q.len - wired_sendsess_reclaim_base(s));
}

/* 1 while anything is still unsent, requeued, or unacknowledged. */
static int sendsess_pending(const wired_sendsess* s) {
  return !wired_sendq_all_sent(&s->q) || s->requeue_n != 0 ||
         wired_sendsess_inflight(s) != 0;
}

int wired_sendsess_done(wired_sendsess* s) {
  if (!s->active) {
    return 0;
  }
  if (sendsess_pending(s)) {
    return 0;
  }
  s->active = 0;
  return 1;
}
