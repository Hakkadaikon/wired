#include "app/http3/server/srvrun/srvrun_impl.h"

static h3prio_candidate srvrun_resp_candidate(const srvrun_conn* c, usz i);
static void             srvrun_prio_build(srvrun_conn* c);
static int              srvrun_any_resp_in_use(const srvrun_conn* c);
static void             srvrun_prio_identity(srvrun_conn* c);
static int srvrun_resp_in_pass(const srvrun_conn* c, usz k, u8 best);
static int srvrun_resp_visit(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz k, u8* best);
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
 * (ascending urgency, ascending stream id within a tie). The pass itself
 * (srvrun_pump_resp_round) sends from the most urgent slots that can send,
 * one slice each, so equal urgencies share it round-robin. */
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
  for (usz k = 0; k < SRVRUN_RESP_SLOTS; k++) {
    c->wtx.resp_urgency[k] = cand[c->prio_order[k]].urgency;
  }
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
    c->prio_order[i]       = i;
    c->wtx.resp_urgency[i] = 0;
  }
}

void srvrun_prio_refresh(srvrun_conn* c) {
  if (srvrun_any_resp_in_use(c)) {
    c->wtx.resp_idle = 0;
    srvrun_prio_build(c);
    return;
  }
  if (c->wtx.resp_idle) {
    return; /* the identity order of the last pass still stands */
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

/* The slot at prio_order position k takes part in this pass: it is in use
 * (a free slot sends nothing, srvrun_pump_one) and no less urgent than the
 * best urgency that has already sent in this pass. */
static int srvrun_resp_in_pass(const srvrun_conn* c, usz k, u8 best) {
  return c->resp[c->prio_order[k]].in_use && c->wtx.resp_urgency[k] <= best;
}

/* Visit position k; a slice sent at urgency u closes the pass to every
 * less urgent slot (RFC 9218 10: higher urgency first, while it can send).
 * A more urgent slot that cannot send leaves the pass open, so a blocked
 * stream never starves the rest. */
static int srvrun_resp_visit(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz k, u8* best) {
  if (!srvrun_resp_in_pass(c, k, *best)) {
    return 0;
  }
  if (!srvrun_pump_one(ctx, c, &c->resp[c->prio_order[k]])) {
    return 0;
  }
  *best = c->wtx.resp_urgency[k];
  return 1;
}

/* One pass over resp[] in prio_order (ascending urgency, then stream id):
 * slots of the most urgent level that can send each get one slice (equal
 * urgencies still share the pass round-robin). */
int srvrun_pump_resp_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = 0;
  u8  best = 0xff;
  for (usz k = 0; k < SRVRUN_RESP_SLOTS; k++) {
    sent |= srvrun_resp_visit(ctx, c, k, &best);
  }
  return sent;
}
