#include "app/http3/server/sendsess/sendsess_impl.h"

static usz  peek_one(const wired_sent_slice* e, u64 lo, u64 hi, u64* newest);
static int  sendsess_hit(const wired_sent_slice* e, u64 lo, u64 hi);
static void sendsess_note_largest(wired_sendsess* s, u64 hi);
static int  sendsess_requeue_acked(
    const wired_sendsess* s, usz i, u64 lo, u64 hi);

/* Fold one log entry into the peek accumulation. */
static usz peek_one(const wired_sent_slice* e, u64 lo, u64 hi, u64* newest) {
  if (!sendsess_hit(e, lo, hi)) {
    return 0;
  }
  if (e->sent_ms > *newest) {
    *newest = e->sent_ms;
  }
  return e->sl.len;
}

usz wired_sendsess_peek_ack(
    const wired_sendsess* s, u64 lo, u64 hi, u64* newest_sent_ms) {
  usz n      = 0;
  u64 newest = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    n += peek_one(&s->log[i], lo, hi, &newest);
  }
  if (n) {
    *newest_sent_ms = newest;
  }
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
  if (!s->has_acked || hi > s->largest_acked) {
    s->largest_acked = hi;
  }
  s->has_acked = 1;
}

void wired_sendsess_ack(wired_sendsess* s, u64 lo, u64 hi) {
  sendsess_note_largest(s, hi);
  s->pto_count = 0; /* the peer is alive: probe budget starts over */
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    if (sendsess_hit(&s->log[i], lo, hi)) {
      sendsess_clear_inflight(s, i);
    }
  }
}

/* 1 if requeue entry i was lost on a packet inside [lo, hi]. */
static int sendsess_requeue_acked(
    const wired_sendsess* s, usz i, u64 lo, u64 hi) {
  u64 pn1 = s->requeue_pn[i];
  return pn1 > lo && pn1 - 1 <= hi;
}

/* Order inside the requeue does not matter (each entry is an independent
 * slice), so a dropped entry is replaced by the last one. */
void wired_sendsess_ack_requeued(wired_sendsess* s, u64 lo, u64 hi) {
  usz i = 0;
  while (i < s->requeue_n) {
    if (!sendsess_requeue_acked(s, i, lo, hi)) {
      i++;
      continue;
    }
    s->requeue_n--;
    s->requeue[i]    = s->requeue[s->requeue_n];
    s->requeue_pn[i] = s->requeue_pn[s->requeue_n];
  }
}
