#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_in_class(
    const srvrun_conn* c, const srvrun_wtsend* w, u32 key);
static u32 srvrun_wt_pass_mask(const srvrun_conn* c);
static int srvrun_wt_in_pass(
    const srvrun_wtsend* w, int keep_open, u32 mask, usz i);
static int srvrun_pump_wt_round_matching(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int keep_open, u32 mask);
static int srvrun_pump_wt_round(const srvrun_step_ctx* ctx, srvrun_conn* c);
static h3prio_candidate srvrun_resp_candidate(const srvrun_conn* c, usz i);
static int srvrun_pump_resp_round(const srvrun_step_ctx* ctx, srvrun_conn* c);
static int srvrun_live_requeued(int in_use, const wired_sendsess* sess);

/* w takes part in this pass's class: no worse than the pass key (a slot
 * better than it cannot send this pass anyway; visiting it only promotes
 * a deferred FIN) and first in its flow. */
static int srvrun_wt_in_class(
    const srvrun_conn* c, const srvrun_wtsend* w, u32 key) {
  return srvrun_wtsend_key(w) <= key && srvrun_wt_flow_ok(c, w);
}

/* The slots taking part in this pass, one bit per slot, fixed before any
 * slot sends so each sends at most one slice per pass. */
static u32 srvrun_wt_pass_mask(const srvrun_conn* c) {
  u32 key  = srvrun_wt_pass_key(c);
  u32 mask = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    mask |= (u32)srvrun_wt_in_class(c, &c->wtsend[i], key) << i;
  return mask;
}

/* w takes part in this pass: it is in the pass's mask and matches
 * keep_open (append_open's own value, not just "is it set right now" -- a
 * slot mid-closing still counts as the keep-open pass so its final
 * slice/FIN is not pushed a whole extra pass behind fresh one-shot
 * arrivals). */
static int srvrun_wt_in_pass(
    const srvrun_wtsend* w, int keep_open, u32 mask, usz i) {
  return (w->append_open != 0) == keep_open && (mask >> i & 1);
}

/* One arrival-order pass over every wtsend slot in this pass's mask. */
static int srvrun_pump_wt_round_matching(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int keep_open, u32 mask) {
  int sent = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (srvrun_wt_in_pass(&c->wtsend[i], keep_open, mask, i))
      sent |= srvrun_pump_one_wt(ctx, c, &c->wtsend[i]);
  return sent;
}

/* The WT-send half of one round-robin pass. RFC 9218 2.1 urgency (plus the
 * fine key and flow order of wired_server_wt_stream_schedule) set by the
 * app (wired_server_wt_stream_priority -- Extended CONNECT carries no
 * per-stream Priority of its own) picks the class: only the best streams
 * that can send take part (srvrun_wt_pass_mask), so a worse class waits
 * until the better one has nothing it can send. Within a class, moqtrun's own
 * two stream shapes (moqtrun.h) give a further proxy: a long-lived
 * append_open relay stream carries one MOQT Object per round (audio, paced
 * ~50/s and loss-tolerant-but-latency-sensitive), while a one-shot stream
 * carries a whole chat message. Draining every append_open slot's one slice
 * before any one-shot slot's at least keeps audio's OWN pass-order
 * position ahead of a chat burst's tail-half slots within a single pass; it
 * does not, by itself, bound how often a pass runs at all -- a live 4-way
 * call with chat every 150ms still showed audio inter-arrival p99 climbing
 * past 500ms with zero relay drops (frames queued, not lost), and this
 * reordering alone did not measurably change that on a CPU-starved test
 * host, so the pass-frequency side of the problem (pacing/poll cadence
 * under contention) remains open. */
static int srvrun_pump_wt_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u32 mask = srvrun_wt_pass_mask(c);
  int sent = srvrun_pump_wt_round_matching(ctx, c, 1, mask);
  return sent | srvrun_pump_wt_round_matching(ctx, c, 0, mask);
}

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
void srvrun_prio_refresh(srvrun_conn* c) {
  h3prio_candidate cand[SRVRUN_RESP_SLOTS];
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    cand[i] = srvrun_resp_candidate(c, i);
  h3prio_order(cand, SRVRUN_RESP_SLOTS, c->prio_order);
}

static int srvrun_pump_resp_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = 0;
  for (usz k = 0; k < SRVRUN_RESP_SLOTS; k++)
    sent |= srvrun_pump_one(ctx, c, &c->resp[c->prio_order[k]]);
  return sent;
}

/* One round-robin pass: try exactly one slice from every in-use resp[] and
 * wtsend slot. resp[] goes FIRST (draft-ietf-webtrans-http3-15 3.2: "From
 * the client's perspective, a WebTransport session is established when the
 * client receives a 2xx response") -- a WT-signalled stream that reaches a
 * peer before that 2xx cannot yet be attributed to any session. A real
 * ngtcp2-webtransport client does exactly this: it silently drops a
 * WT-typed uni stream it cannot associate, confirmed by both a live capture
 * (the server's own qlog showed 5 uni GETs sent at pn 2-6, the session's
 * 2xx only at pn 7) and a same-implementation ngtcp2-server comparison run
 * (2xx and its uni streams land in the SAME packet, 2xx first). The
 * opposite order let a session established and its first WT streams opened
 * in the same pump pass -- e.g. an on_session callback that opens streams
 * immediately, this SDK's own interop example among them -- race the 2xx
 * out AFTER them, which peers may not tolerate.
 * @return 1 if any slot actually sent one. */
int srvrun_pump_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = srvrun_pump_resp_round(ctx, c);
  return sent | srvrun_pump_wt_round(ctx, c);
}

/* 1 if in-use slot sess has a PTO probe queued (a freed slot's leftover
 * requeue never sends, so it must not bypass pacing either). */
static int srvrun_live_requeued(int in_use, const wired_sendsess* sess) {
  return in_use && srvrun_has_requeued(sess);
}

/* 1 if any resp[] slot has a PTO probe queued. */
int srvrun_any_resp_requeued(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (srvrun_live_requeued(c->resp[i].in_use, &c->resp[i].sess)) return 1;
  return 0;
}

/* 1 if any WT send slot has a PTO probe queued. */
int srvrun_any_wtsend_requeued(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (srvrun_live_requeued(c->wtsend[i].in_use, &c->wtsend[i].sess)) return 1;
  return 0;
}
