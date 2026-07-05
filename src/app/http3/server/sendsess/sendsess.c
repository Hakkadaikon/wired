#include "app/http3/server/sendsess/sendsess.h"

void wired_sendsess_arm(
    wired_sendsess* s, const u8* stream, usz len, usz chunk) {
  wired_sendq_init(&s->q, stream, len, chunk);
  s->active        = 1;
  s->requeue_n     = 0;
  s->largest_acked = 0;
  s->has_acked     = 0;
  s->pto_count     = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) s->log[i].inflight = 0;
}

usz wired_sendsess_inflight(const wired_sendsess* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    n += (usz)(s->log[i].inflight != 0);
  return n;
}

int wired_sendsess_take(wired_sendsess* s, wired_sendq_slice* out) {
  if (s->requeue_n) {
    *out = s->requeue[--s->requeue_n];
    return 1;
  }
  return wired_sendq_next(&s->q, out);
}

/* First free log slot, or -1 when every slot is in flight. */
static int sendsess_free_slot(const wired_sendsess* s) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (!s->log[i].inflight) return (int)i;
  return -1;
}

int wired_sendsess_sent(
    wired_sendsess* s, const wired_sendq_slice* sl, u64 pn, u64 now_ms) {
  int i = sendsess_free_slot(s);
  if (i < 0) return 0;
  s->log[i].pn       = pn;
  s->log[i].sl       = *sl;
  s->log[i].inflight = 1;
  s->log[i].sent_ms  = now_ms;
  return 1;
}

usz wired_sendsess_inflight_bytes(const wired_sendsess* s) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (s->log[i].inflight) n += s->log[i].sl.len;
  return n;
}

static int sendsess_hit(const wired_sent_slice* e, u64 lo, u64 hi);

/* Fold one log entry into the peek accumulation. */
static usz peek_one(const wired_sent_slice* e, u64 lo, u64 hi, u64* newest) {
  if (!sendsess_hit(e, lo, hi)) return 0;
  if (e->sent_ms > *newest) *newest = e->sent_ms;
  return e->sl.len;
}

usz wired_sendsess_peek_ack(
    const wired_sendsess* s, u64 lo, u64 hi, u64* newest_sent_ms) {
  usz n      = 0;
  u64 newest = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    n += peek_one(&s->log[i], lo, hi, &newest);
  if (n) *newest_sent_ms = newest;
  return n;
}

int wired_sendsess_covered(const wired_sent_slice* e, u64 lo, u64 hi) {
  return e->inflight && e->pn >= lo && e->pn <= hi;
}

/* 1 if in-flight entry e is acknowledged by [lo, hi]. */
static int sendsess_hit(const wired_sent_slice* e, u64 lo, u64 hi) {
  return wired_sendsess_covered(e, lo, hi);
}

/* Track the highest acknowledged pn; it never regresses. */
static void sendsess_note_largest(wired_sendsess* s, u64 hi) {
  if (!s->has_acked || hi > s->largest_acked) s->largest_acked = hi;
  s->has_acked = 1;
}

void wired_sendsess_ack(wired_sendsess* s, u64 lo, u64 hi) {
  sendsess_note_largest(s, hi);
  s->pto_count = 0; /* the peer is alive: probe budget starts over */
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (sendsess_hit(&s->log[i], lo, hi)) s->log[i].inflight = 0;
}

/* RFC 9002 6.1.1: 1 if in-flight entry e is past the packet threshold. */
static int sendsess_lost(const wired_sent_slice* e, u64 largest_acked) {
  return e->inflight && largest_acked >= 3 && e->pn <= largest_acked - 3;
}

/* Move log entry i's slice to the requeue (dropped silently if full — the
 * next detect pass picks it up again since the entry stays in flight). */
static void sendsess_requeue(wired_sendsess* s, usz i) {
  if (s->requeue_n >= WIRED_SENDSESS_LOG) return;
  s->requeue[s->requeue_n++] = s->log[i].sl;
  s->log[i].inflight         = 0;
}

/* Report one lost pn to the caller's array (skipped without one). */
static void sendsess_report_lost(u64 pn, u64* lost_pns, usz cap, usz i) {
  if (lost_pns && i < cap) lost_pns[i] = pn;
}

usz wired_sendsess_detect_lost(
    wired_sendsess* s, u64 largest_acked, u64* lost_pns, usz cap) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (sendsess_lost(&s->log[i], largest_acked)) {
      sendsess_report_lost(s->log[i].pn, lost_pns, cap, n);
      sendsess_requeue(s, i);
      n++;
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
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (sendsess_older(s, best, i)) best = (int)i;
  return best;
}

int wired_sendsess_pto_fire(wired_sendsess* s, int max) {
  int i = sendsess_oldest(s);
  if (i < 0) return 1;
  if (s->pto_count >= max) return 0;
  s->pto_count++;
  sendsess_requeue(s, (usz)i);
  return 1;
}

/* 1 while anything is still unsent, requeued, or unacknowledged. */
static int sendsess_pending(const wired_sendsess* s) {
  return !wired_sendq_all_sent(&s->q) || s->requeue_n != 0 ||
         wired_sendsess_inflight(s) != 0;
}

int wired_sendsess_done(wired_sendsess* s) {
  if (!s->active) return 0;
  if (sendsess_pending(s)) return 0;
  s->active = 0;
  return 1;
}
