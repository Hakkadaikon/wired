#include "app/http3/server/srvrun/srvrun_impl.h"

static h3prio_candidate srvrun_resp_candidate(const srvrun_conn* c, usz i);
static void             srvrun_prio_build(srvrun_conn* c);
static int              srvrun_any_resp_in_use(const srvrun_conn* c);
static void             srvrun_prio_identity(srvrun_conn* c);
static int srvrun_live_requeued(int in_use, const wired_sendsess* sess);

/* resp[] slot i's current RFC 9218 priority, read from the receive-side
 * streams[] table (wired_srvloop_priority_of) rather than stored on
 * srvrun_resp itself -- streams[] is the one place a PRIORITY_UPDATE lands
 * (priority_ctrl.c), so reading it here keeps a single source of truth
 * instead of a second copy that could drift. An in_use resp[] slot with no
 * matching streams[] slot (already released, e.g. mid-teardown) reads as
 * the RFC 9218 4.1 default -- it still sends, just without a live urgency
 * signal, matching the pre-scheduling behavior for that edge case. */
static h3prio_candidate srvrun_resp_candidate(const srvrun_conn* c, usz i) {
  h3prio_candidate cand = {
      H3_URGENCY_DEFAULT, 0, c->resp[i].stream_id, c->resp[i].in_use};
  h3_priority p;
  if (c->resp[i].in_use &&
      wired_srvloop_priority_of(&c->l, c->resp[i].stream_id, &p)) {
    cand.urgency     = p.urgency;
    cand.incremental = p.incremental;
  }
  return cand;
}

/* RFC 9218 10: one pacing-unrelated pass over resp[] in priority order
 * (ascending urgency, ascending stream id within a tie -- see
 * h3prio_order's own doc for why this ordering also covers
 * incremental bandwidth sharing and same-urgency starvation avoidance
 * without extra machinery: every slot still gets exactly one slice per
 * pass, only the visiting order within a pass changed). */
/* (Re)build c->prio_order for the coming pump pass. Claims, releases, and
 * PRIORITY_UPDATEs all land between passes (reap/start/receive run before
 * srvrun_pump_sess in the step), so one build per pass sees exactly what a
 * per-round build used to. */
static void srvrun_prio_build(srvrun_conn* c) {
  h3prio_candidate cand[SRVRUN_RESP_SLOTS];
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    cand[i] = srvrun_resp_candidate(c, i);
  }
  h3prio_order(cand, SRVRUN_RESP_SLOTS, c->prio_order);
}

static int srvrun_any_resp_in_use(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      return 1;
    }
  }
  return 0;
}

/* With no response in flight the order decides nothing (srvrun_pump_one
 * skips a free slot), so the pass keeps a valid visiting order without
 * sorting SRVRUN_RESP_SLOTS candidates -- the usual state of a connection
 * that only carries WebTransport. */
static void srvrun_prio_identity(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    c->prio_order[i] = i;
  }
}

void srvrun_prio_refresh(srvrun_conn* c) {
  if (srvrun_any_resp_in_use(c)) {
    c->wtx.resp_idle = 0;
    srvrun_prio_build(c);
    return;
  }
  srvrun_prio_identity(c);
  c->wtx.resp_idle = 1;
}

/* 1 if in-use slot sess has a PTO probe queued (a freed slot's leftover
 * requeue never sends, so it must not bypass pacing either). */
static int srvrun_live_requeued(int in_use, const wired_sendsess* sess) {
  return in_use && srvrun_has_requeued(sess);
}

/* 1 if any resp[] slot has a PTO probe queued. */
int srvrun_any_resp_requeued(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (srvrun_live_requeued(c->resp[i].in_use, &c->resp[i].sess)) {
      return 1;
    }
  }
  return 0;
}

/* 1 if any WT send slot has a PTO probe queued. */
int srvrun_any_wtsend_requeued(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (srvrun_live_requeued(c->wtsend[i].in_use, &c->wtsend[i].sess)) {
      return 1;
    }
  }
  return 0;
}
