#include "app/http3/server/srvrun/srvrun_impl.h"
#include "common/bytes/util/bits.h"

static int srvrun_wt_in_class(
    const srvrun_conn* c, const srvrun_wtsend* w, u32 key, u64 live);
static u64 srvrun_wt_pass_mask(srvrun_conn* c, u64 live);
static u64 srvrun_wt_work_mask(const srvrun_conn* c, u64 mask);
static int srvrun_wt_in_pass(
    const srvrun_wtsend* w, int keep_open, u64 mask, usz i);
static int srvrun_pump_wt_round_matching(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int keep_open, u64 mask);
static int srvrun_pump_wt_round(const srvrun_step_ctx* ctx, srvrun_conn* c);
static int srvrun_pump_resp_round(const srvrun_step_ctx* ctx, srvrun_conn* c);

/* w takes part in this pass's class: no worse than the pass key (a slot
 * better than it cannot send this pass anyway; visiting it only promotes
 * a deferred FIN) and first in its flow. */
static int srvrun_wt_in_class(
    const srvrun_conn* c, const srvrun_wtsend* w, u32 key, u64 live) {
  return srvrun_wtsend_key(w) <= key && srvrun_wt_flow_ok(c, w, live);
}

/* The in-use WT send slots, one bit per slot. A pump round walks only
 * these: a free slot never sends (srvrun_pump_one_wt), is never ready and
 * never counts toward a session's share, so skipping it changes nothing
 * but the cost of a round that has little or nothing to send. */
u64 srvrun_wtsend_live_scan(const srvrun_conn* c) {
  u64 live = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    live |= (u64)(c->wtsend[i].in_use != 0) << i;
  }
  return live;
}

/* The same mask as srvrun_wtsend_live_scan, looking only at the slots not
 * already known free (srvrun_conn.wtx.send_free), and remembering the free
 * ones it finds: this runs on every pump round, most of them idle. */
u64 srvrun_wtsend_live(srvrun_conn* c) {
  u64 all  = ~(u64)0 >> (64 - SRVRUN_WT_SEND_SLOTS);
  u64 live = 0;
  for (u64 b = all & ~c->wtx.send_free; b; b &= b - 1) {
    usz i = bits_ctz64(b);
    live |= (u64)(c->wtsend[i].in_use != 0) << i;
  }
  c->wtx.send_free = all & ~live;
  return live;
}

/* The slots taking part in this pass, one bit per slot, fixed before any
 * slot sends so each sends at most one slice per pass, then evened out
 * across sessions (srvrun_wt_fair_mask, draft-ietf-webtrans-http3-16 8). */
static u64 srvrun_wt_pass_mask(srvrun_conn* c, u64 live) {
  u32 key  = srvrun_wt_pass_key(c, live);
  u64 mask = 0;
  for (u64 b = live; b; b &= b - 1) {
    usz i = bits_ctz64(b);
    mask |= (u64)srvrun_wt_in_class(c, &c->wtsend[i], key, live) << i;
  }
  return srvrun_wt_fair_mask(c, mask);
}

/* The slots of mask a pump visit can do anything for. Visiting a slot with
 * nothing to send, resend or FIN only re-reads its gates, and the one
 * effect that can have is DATA_BLOCKED (srvrun_notify_conn_blocked) -- so
 * such slots are skipped while the connection credit has room, and every
 * slot is still visited once it has none. */
static u64 srvrun_wt_work_mask(const srvrun_conn* c, u64 mask) {
  u64 work = 0;
  if (!srvrun_conn_credit_has_room(c)) {
    return mask;
  }
  for (u64 b = mask; b; b &= b - 1) {
    usz i = bits_ctz64(b);
    work |= (u64)srvrun_wtsend_wants_pump(&c->wtsend[i]) << i;
  }
  return work;
}

/* w takes part in this pass: it is in the pass's mask and matches
 * keep_open (append_open's own value, not just "is it set right now" -- a
 * slot mid-closing still counts as the keep-open pass so its final
 * slice/FIN is not pushed a whole extra pass behind fresh one-shot
 * arrivals). */
static int srvrun_wt_in_pass(
    const srvrun_wtsend* w, int keep_open, u64 mask, usz i) {
  return (w->append_open != 0) == keep_open && (mask >> i & 1);
}

/* One arrival-order pass over every wtsend slot in this pass's mask. */
static int srvrun_pump_wt_round_matching(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int keep_open, u64 mask) {
  int sent = 0;
  for (u64 b = mask; b; b &= b - 1) {
    usz i = bits_ctz64(b);
    if (srvrun_wt_in_pass(&c->wtsend[i], keep_open, mask, i)) {
      sent |= srvrun_pump_one_wt(ctx, c, &c->wtsend[i]);
    }
  }
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
  u64 live = srvrun_wtsend_live(c);
  u64 mask;
  int sent;
  /* nothing to send, resend or FIN on any slot: the pass would pick a
   * class and share it out only to visit no one */
  if (!srvrun_wt_work_mask(c, live)) {
    return 0;
  }
  mask = srvrun_wt_pass_mask(c, live);
  mask &= srvrun_wt_work_mask(c, mask);
  sent = srvrun_pump_wt_round_matching(ctx, c, 1, mask);
  return sent | srvrun_pump_wt_round_matching(ctx, c, 0, mask);
}

static int srvrun_pump_resp_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = 0;
  for (usz k = 0; k < SRVRUN_RESP_SLOTS; k++) {
    srvrun_resp* r = &c->resp[c->prio_order[k]];
    /* a free slot sends nothing (srvrun_pump_one): skip the call */
    if (r->in_use) {
      sent |= srvrun_pump_one(ctx, c, r);
    }
  }
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
  /* resp_idle: no response in flight when this pass began, none since */
  int sent = c->wtx.resp_idle ? 0 : srvrun_pump_resp_round(ctx, c);
  return sent | srvrun_pump_wt_round(ctx, c);
}
