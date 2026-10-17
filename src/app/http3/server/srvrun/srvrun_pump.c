#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_pump_one_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r);

/* RFC 9000 4.1/19.10: apply EVERY distinct MAX_STREAM_DATA slot this step
 * latched (dispatch.c's gather_one_max_stream_data) -- several parallel
 * streamed responses can each be raised in the same step, and applying only
 * one would leave the rest stuck at their prior credit ceiling forever. */
void srvrun_apply_stream_credit_update(srvrun_conn* c) {
  usz n                  = c->l.max_stream_data_n;
  c->l.max_stream_data_n = 0;
  for (usz i = 0; i < n; i++) {
    srvrun_apply_one_stream_credit_update(c, i);
  }
}

/* RFC 9002 7.5: "Probe packets MUST NOT be blocked by the congestion
 * controller." A PTO probe is a retransmit of an already-in-flight slice
 * that wired_sendsess_pto_fire moved to r->sess's requeue (sendsess.c) --
 * gating it on cwnd re-creates the exact deadlock RFC 9002 7.5 forbids: cwnd
 * can only grow from new ACKs, new ACKs need new sends, and a probe stuck
 * behind a full cwnd is the one send that would produce that ACK. */
int srvrun_has_requeued(const wired_sendsess* sess) {
  return sess->requeue_n != 0;
}

/* RFC 9000 4.1/19.12: tell the peer THIS connection ran out of send credit,
 * once per distinct ceiling (data_blocked_sent_at != c->conn_credit -- a
 * later MAX_DATA raise makes a stale sent-at send again if blocked a second
 * time). Without this, a peer whose own autotuning lags a fast multi-stream
 * transfer never learns the SERVER is blocked and has no signal to raise
 * MAX_DATA sooner -- the connection stalls until the peer's own heuristics
 * eventually catch up, or the idle timeout fires first (RFC 9000 10.1).
 * A no-op while conn_credit still has room: only the connection-wide ceiling
 * blocking (not a per-stream credit or cwnd/log gate) warrants this signal,
 * same scope DATA_BLOCKED itself carries (STREAM_DATA_BLOCKED would be the
 * per-stream counterpart, not needed here since srvloop already raises
 * stream credit independently via MAX_STREAM_DATA). */
void srvrun_notify_conn_blocked(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (srvrun_conn_credit_has_room(c)) {
    return;
  }
  if (c->data_blocked_sent_at == c->conn_credit) {
    return;
  }
  srvrun_send_data_blocked(cfg, c, c->conn_credit);
  c->data_blocked_sent_at = c->conn_credit;
}

/* RFC 9000 4.6/19.14: srvrun_notify_conn_blocked's uni-stream mirror. A
 * server-initiated uni open (moqtrun's relay streams) refused by peer_uni_
 * stream_limit latches uni_blocked_seen at the call site (srvrun_wt_uni_
 * grant_ok, which has no srvrun_cfg); this drains that latch once per pump
 * pass and sends STREAMS_BLOCKED(uni) at most once per distinct ceiling
 * (uni_blocked_sent_at), the same one-signal-per-raise shape as the bidi/
 * DATA_BLOCKED siblings. Without this, a peer that only re-grants MAX_
 * STREAMS(uni) on seeing this signal never learns the relay is stuck, and
 * every relay open keeps failing until the connection ends. */
void srvrun_notify_uni_blocked(const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 limit = srvrun_peer_uni_limit(c);
  if (!c->uni_blocked_seen) {
    return;
  }
  c->uni_blocked_seen = 0;
  if (c->uni_blocked_sent_at == limit) {
    return;
  }
  srvrun_send_streams_blocked(cfg, c, 1, limit);
  c->uni_blocked_sent_at = limit;
}

/* 1 when sess may send right now: a queued probe retransmit only needs the
 * log gate (RFC 9002 7.5 bypasses cwnd for it); brand-new data needs both
 * gates. The log gate is checked for a probe too, even though
 * sendsess_requeue (sendsess.c) already cleared its log entry's inflight
 * flag the moment it moved to requeue -- so requeue_n != 0 always implies
 * at least that many free log entries, and this check can never actually
 * fail for a probe. It stays as an explicit invariant, not dead code: it
 * documents that a probe's cwnd exemption is deliberately narrower than a
 * blanket "requeue bypasses everything". */
int srvrun_pump_gate_ok(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  if (srvrun_has_requeued(sess)) {
    return srvrun_sess_log_room(sess);
  }
  return srvrun_can_send_new(c, sess, credit);
}

/* Send one slice from r if the gates allow and one is ready. Pacing's
 * next-send time is scheduled once per whole pass by the caller
 * (srvrun_pump_round_gated), not per slice. */
static int srvrun_pump_one_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r) {
  wired_sendq_slice sl;
  if (!srvrun_pump_gate_ok(c, &r->sess, r->stream_credit)) {
    srvrun_notify_conn_blocked(ctx->cfg, c);
    return 0;
  }
  if (!wired_sendsess_take(&r->sess, &sl)) {
    return 0;
  }
  return srvrun_send_slice(ctx, c, r, &sl);
}

/* Delta-adjust the cached totals around one slice attempt: only this sess's
 * contribution can change inside it (take/untake/sent), so the before/after
 * difference is exact -- and unsigned wraparound adds a negative delta
 * correctly. */
int srvrun_pump_one(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r) {
  /* RFC 9000 3.1: a freed slot (reaped, or reset by srvrun_resp_stop) keeps
   * its stale sess; no STREAM frame may follow its RESET_STREAM. */
  if (!r->in_use) {
    return 0;
  }
  usz inf0 = wired_sendsess_inflight_bytes(&r->sess);
  usz con0 = srvrun_sess_consumed(&r->sess);
  int sent = srvrun_pump_one_slice(ctx, c, r);
  usz inf1 = wired_sendsess_inflight_bytes(&r->sess);
  c->acct_inflight += inf1 - inf0;
  c->acct_consumed += srvrun_sess_consumed(&r->sess) - con0;
  if (sent) {
    srvrun_pace_charge(c, inf1 - inf0);
  }
  return sent;
}

/* The wire FIN belongs on exactly the slice that ends the stream: the
 * slot is past its final append (append_open 0) and sl ends at the
 * cumulative stream offset. sl->fin (end of the CURRENT epoch buffer) is
 * deliberately ignored: rounds can be staged behind an already-logged
 * slice (wired_sendsess_extend), so a retransmit of a stale
 * end-of-buffer slice must not carry FIN at what is by then a mid-stream
 * offset (RFC 9000 4.5: a final size that moves is FINAL_SIZE_ERROR). */
u8 srvrun_wt_slice_fin(const srvrun_wtsend* w, const wired_sendq_slice* sl) {
  return (u8)(!w->append_open &&
              wired_sendsess_stream_offset(&w->sess, sl) + sl->len ==
                  w->stream_off);
}

/* Sends w's pending bare-FIN round (srvrun_wtsend.fin_only_pending's own
 * doc): a synthetic 0-byte/fin=1 slice, since wired_sendsess_take never
 * yields one for w's 0-byte arm. Clears fin_only_pending and append_open
 * (the stream really is over now) once the slice is on the wire; the slot
 * itself reaps later, same as any other final round, once this one's ACK
 * lands (srvrun_wtsend_finished). */
int srvrun_pump_wt_fin_only(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendq_slice sl = {0, 0, 1};
  if (!w->fin_only_pending) {
    return 0;
  }
  if (!srvrun_send_stream_slice(ctx, c, &w->sess, w->stream_id, &sl, 1)) {
    return 0;
  }
  w->fin_only_pending = 0;
  w->append_open      = 0;
  return 1;
}

/* Promotes a deferred wired_server_wt_stream_fin request to fin_only_pending
 * the moment w's previous round finishes (srvrun_wtsend_request_fin's own
 * doc on why the request could not be armed immediately). No-op once
 * already promoted or if nothing was ever requested. */
void srvrun_wtsend_promote_fin_if_ready(
    const srvrun_conn* c, srvrun_wtsend* w) {
  if (!w->fin_requested) {
    return;
  }
  if (!wired_sendsess_done(&w->sess)) {
    return;
  }
  w->fin_requested = 0;
  srvrun_wtsend_start_fin_now(c, w);
}
