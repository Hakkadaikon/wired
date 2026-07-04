#include "app/http3/server/sendsess/sendsess.h"

void wired_sendsess_arm(
    wired_sendsess* s, const u8* stream, usz len, usz chunk) {
  wired_sendq_init(&s->q, stream, len, chunk);
  s->active    = 1;
  s->requeue_n = 0;
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
    wired_sendsess* s, const wired_sendq_slice* sl, u64 pn) {
  int i = sendsess_free_slot(s);
  if (i < 0) return 0;
  s->log[i].pn       = pn;
  s->log[i].sl       = *sl;
  s->log[i].inflight = 1;
  return 1;
}

/* 1 if in-flight entry e is acknowledged by [lo, hi]. */
static int sendsess_hit(const wired_sent_slice* e, u64 lo, u64 hi) {
  return e->inflight && e->pn >= lo && e->pn <= hi;
}

void wired_sendsess_ack(wired_sendsess* s, u64 lo, u64 hi) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (sendsess_hit(&s->log[i], lo, hi)) s->log[i].inflight = 0;
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
