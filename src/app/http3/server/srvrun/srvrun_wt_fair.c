#include "app/http3/server/srvrun/srvrun_impl.h"

/* draft-ietf-webtrans-http3-16 8 (WTH3-083): "each session that shares a
 * transport connection gets a reasonable share of controlled resources;
 * this applies both to sending data and to opening new streams".
 *
 * Sending: within one pump pass (srvrun_wt_pass_mask), every session that
 * has ready streams sends the same number of slices -- the smallest ready
 * count among them -- so a session cannot buy a bigger share of the link
 * by opening more streams. Each session's cursor rotates which of its
 * streams take the pass, keeping them round-robin among themselves.
 * Connection plumbing (wt_session_slot < 0) is never capped. */

/* One session's keep scan over the pass mask. */
typedef struct {
  u32 mask;
  u32 kept;
  u32 quota;
  usz last;
} srvrun_wt_fair_scan;

static int  srvrun_wt_fair_sess(const srvrun_wtsend* w, u32 mask, usz i, int s);
static u32  srvrun_wt_sess_ready(const srvrun_conn* c, u32 mask, int s);
static u32  srvrun_wt_min_nz(u32 q, u32 n);
static u32  srvrun_wt_fair_quota(const srvrun_conn* c, u32 mask);
static void srvrun_wt_fair_visit(srvrun_wt_fair_scan* f, usz i);
static u32  srvrun_wt_fair_keep(srvrun_conn* c, u32 mask, int s, u32 quota);
static int  srvrun_wt_held(const srvrun_conn* c, int s);

/* Slot i is live, in the pass, and belongs to session slot s (the class
 * mask also marks free slots: pumping one is a no-op, but a zeroed free
 * slot's owner reads as session 0). */
static int srvrun_wt_fair_sess(const srvrun_wtsend* w, u32 mask, usz i, int s) {
  return w->in_use && (mask >> i & 1) && w->wt_session_slot == s;
}

/* Session s's slots in the pass. */
static u32 srvrun_wt_sess_ready(const srvrun_conn* c, u32 mask, int s) {
  u32 n = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    n += (u32)srvrun_wt_fair_sess(&c->wtsend[i], mask, i, s);
  }
  return n;
}

/* The smaller of q and a non-zero n. */
static u32 srvrun_wt_min_nz(u32 q, u32 n) { return n && n < q ? n : q; }

/* The per-session slice quota of this pass: the smallest ready count of
 * the sessions with any, or no cap (~0) while at most one competes. */
static u32 srvrun_wt_fair_quota(const srvrun_conn* c, u32 mask) {
  u32 q    = ~0u;
  int busy = 0;
  for (int s = 0; s < SRVRUN_MAX_WT_SESSIONS; s++) {
    u32 n = srvrun_wt_sess_ready(c, mask, s);
    q     = srvrun_wt_min_nz(q, n);
    busy += n != 0;
  }
  return busy > 1 ? q : ~0u;
}

/* Keep slot i while the quota lasts, else drop it from the pass. */
static void srvrun_wt_fair_visit(srvrun_wt_fair_scan* f, usz i) {
  if (f->kept < f->quota) {
    f->kept++;
    f->last = i;
    return;
  }
  f->mask &= ~(1u << i);
}

/* Keep `quota` of session s's pass slots, scanning from its cursor; the
 * cursor moves past the last one kept so the rest go first next pass. */
static u32 srvrun_wt_fair_keep(srvrun_conn* c, u32 mask, int s, u32 quota) {
  usz                 start = c->wtx.fair_next[s];
  srvrun_wt_fair_scan f = {mask, 0, quota, start + SRVRUN_WT_SEND_SLOTS - 1};
  for (usz k = 0; k < SRVRUN_WT_SEND_SLOTS; k++) {
    usz i = (start + k) % SRVRUN_WT_SEND_SLOTS;
    if (srvrun_wt_fair_sess(&c->wtsend[i], mask, i, s)) {
      srvrun_wt_fair_visit(&f, i);
    }
  }
  c->wtx.fair_next[s] = (u8)((f.last + 1) % SRVRUN_WT_SEND_SLOTS);
  return f.mask;
}

u32 srvrun_wt_fair_mask(srvrun_conn* c, u32 mask) {
  u32 q = srvrun_wt_fair_quota(c, mask);
  for (int s = 0; s < SRVRUN_MAX_WT_SESSIONS; s++) {
    mask = srvrun_wt_fair_keep(c, mask, s, q);
  }
  return mask;
}

/* Send slots held by session slot s (s < 0: connection plumbing). */
static int srvrun_wt_held(const srvrun_conn* c, int s) {
  int n = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    n += c->wtsend[i].in_use && c->wtsend[i].wt_session_slot == s;
  }
  return n;
}

/* Opening: session slot sidx may claim one more send slot while it holds
 * fewer than its share -- the slots plumbing does not hold, split evenly
 * among the active sessions -- so one session cannot fill the shared
 * table and starve the other's opens. */
int srvrun_wt_open_share_ok(const srvrun_conn* c, int sidx) {
  int n = 0;
  for (int s = 0; s < SRVRUN_MAX_WT_SESSIONS; s++) {
    n += srvrun_wt_is_active(c, s);
  }
  n += !n;
  return srvrun_wt_held(c, sidx) <
         ((int)SRVRUN_WT_SEND_SLOTS - srvrun_wt_held(c, -1)) / n;
}
