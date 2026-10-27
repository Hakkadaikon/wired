#include "app/http3/server/sendsess/sendsess_impl.h"

static usz sendsess_live_min(usz off, int live, usz base);
static usz sendsess_log_min_off(const wired_sendsess* s, usz base);
static usz sendsess_requeue_min_off(const wired_sendsess* s, usz base);
static int sendsess_pending(const wired_sendsess* s);

/* Ring-storage reclaim floor and session completion: what stays live once
 * slices are acknowledged, lost or requeued. */

/* off if it is live (a candidate the retransmit path may still read) and
 * lower than the running minimum, else the minimum unchanged. */
static usz sendsess_live_min(usz off, int live, usz base) {
  return live && off < base ? off : base;
}

/* Fold the in-flight log's offsets into the running minimum. */
static usz sendsess_log_min_off(const wired_sendsess* s, usz base) {
  for (usz i = 0; i < s->log_hi; i++) {
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
