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
static int sendsess_live_above(const wired_sent_slice* e, u64 above1);
static int sendsess_older(const wired_sendsess* s, int best, usz i, u64 above1);
static int sendsess_oldest_above(const wired_sendsess* s, u64 above1);
static void sendsess_copy(wired_sendsess* s, int i);

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
  s->requeue_pn[s->requeue_n] = s->log[i].pn + 1;
  s->requeue[s->requeue_n++]  = s->log[i].sl;
  sendsess_clear_inflight(s, i);
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
  for (usz i = 0; i < s->log_hi; i++) {
    if (sendsess_lost(&s->log[i], largest_acked, now_ms, loss_delay_us)) {
      sendsess_report_lost(s, &s->log[i], lost, cap, n);
      sendsess_requeue(s, i);
      n++;
    }
  }
  return n;
}

/* 1 if log entry e is in flight with pn + 1 > above1 (0: any pn). */
static int sendsess_live_above(const wired_sent_slice* e, u64 above1) {
  return e->inflight && e->pn + 1 > above1;
}

/* 1 if log[i] is live above above1 and older (smaller pn) than log[best]. */
static int sendsess_older(
    const wired_sendsess* s, int best, usz i, u64 above1) {
  return sendsess_live_above(&s->log[i], above1) &&
         (best < 0 || s->log[i].pn < s->log[(usz)best].pn);
}

/* Index of the oldest in-flight entry with pn + 1 > above1, -1 if none. */
static int sendsess_oldest_above(const wired_sendsess* s, u64 above1) {
  int best = -1;
  for (usz i = 0; i < s->log_hi; i++) {
    if (sendsess_older(s, best, i, above1)) {
      best = (int)i;
    }
  }
  return best;
}

int wired_sendsess_oldest_sent_ms(const wired_sendsess* s, u64* out) {
  int i = sendsess_oldest_above(s, 0);
  if (i < 0) {
    return 0;
  }
  *out = s->log[(usz)i].sent_ms;
  return 1;
}

/* Queue a copy of log entry i for a probe resend; the entry itself stays
 * in flight. Nothing is queued for i < 0 or a full requeue. */
static void sendsess_copy(wired_sendsess* s, int i) {
  if (i < 0 || s->requeue_n >= WIRED_SENDSESS_LOG) {
    return;
  }
  s->requeue_pn[s->requeue_n] = s->log[(usz)i].pn + 1;
  s->requeue[s->requeue_n++]  = s->log[(usz)i].sl;
}

/* RFC 9002 6.2: a PTO is not a loss, so the probed packets stay in flight;
 * 6.2.4: up to two probe datagrams, the two oldest in-flight slices. */
int wired_sendsess_pto_probe(wired_sendsess* s) {
  int a = sendsess_oldest_above(s, 0);
  if (a < 0 || s->requeue_n) {
    return 0;
  }
  sendsess_copy(s, a);
  sendsess_copy(s, sendsess_oldest_above(s, s->log[(usz)a].pn + 1));
  return 1;
}

int wired_sendsess_pto_fire(wired_sendsess* s, int max) {
  if (sendsess_oldest_above(s, 0) < 0) {
    return 1;
  }
  if (s->pto_count >= max) {
    return 0;
  }
  s->pto_count++;
  (void)wired_sendsess_pto_probe(s);
  return 1;
}
