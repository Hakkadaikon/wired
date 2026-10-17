#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_any_resp_active(const srvrun_conn* c);
static int srvrun_any_wtsend_active(const srvrun_conn* c);
static int srvrun_any_send_active(const srvrun_conn* c);

void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (c->closing) {
    return; /* RFC 9000 10.2.1: no response, pump, or ACK */
  }
  srvrun_feed_acks(ctx, ctx->cfg, c);
  srvrun_acct_resync(c);
  cc_bbr_tick(&c->cc, c->acct_inflight, ctx->now_ms);
  srvrun_apply_conn_credit_update(c);
  srvrun_apply_stream_credit_update(c);
  srvrun_apply_uni_limit_update(c);
  srvrun_reap_resps(ctx, c, slot);
  srvrun_reap_wtsends(c);
  srvrun_reannounce_stream_limit(ctx->cfg, c, srvrun_stream_limit_base(ctx));
  srvrun_reannounce_uni_stream_limit(ctx->cfg, c);
  srvrun_abort_incomplete_reqs(ctx, slot);
  srvrun_abort_frame_unexpected_reqs(ctx, slot);
  srvrun_start_held_resps(ctx, slot);
  srvrun_start_done_resps(ctx, slot);
  srvrun_pump_sess(ctx, slot);
  srvrun_pump_datagram(ctx, c);
  srvrun_flush_deferred_ack(ctx, c);
  srvrun_ku_discard_stale(c, ctx->now_ms);
  srvrun_qlog_metrics(ctx, c);
}

/* 1 if any resp[] slot is in use -- a connection with at least one response
 * still being built or in flight. */
static int srvrun_any_resp_active(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      return 1;
    }
  }
  return 0;
}

/* 1 if any WT send slot is in use -- the wtsend side of the same check. */
static int srvrun_any_wtsend_active(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (c->wtsend[i].in_use) {
      return 1;
    }
  }
  return 0;
}

/* 1 if any send session (resp[] or wtsend) is still in flight. */
static int srvrun_any_send_active(const srvrun_conn* c) {
  return srvrun_any_resp_active(c) || srvrun_any_wtsend_active(c);
}

/* 1 while this slot still owes stream bytes (in flight, paced, or window
 * blocked) — the loop must keep ticking for it. */
int srvrun_sess_waiting(const srvrun_conn* c) {
  return c->up && srvrun_any_send_active(c);
}

/* 1 while this slot has anything outbound that only a poll-loop tick (not
 * this connection's own next receive) will flush: an in-flight HTTP
 * response (srvrun_sess_waiting) or a broadcast DATAGRAM (dg_pending, RFC
 * 9221 5 -- queued by srvrun_broadcast_to_all/srvrun_bcast_drain_self but
 * only ever flushed from srvrun_pump_datagram, which srvrun_sess_on_step
 * reaches only when THIS connection itself next receives something). Used
 * only to decide whether the loop must keep ticking (srvrun_any_waiting);
 * NOT for the PTO probe/teardown decision below, which is specifically
 * about wired_sendsess retransmission and must not fire for a connection
 * that merely has a queued DATAGRAM and no HTTP response in flight. */
int srvrun_has_outbound(const srvrun_conn* c) {
  return c->up && (srvrun_any_send_active(c) || c->dg_pending);
}

/* 1 if c has a boot flight outstanding, awaiting confirm -- true regardless
 * of resp[]/wtsend[] activity (none is possible before confirm anyway).
 * srvrun_boot_pto_slot only ever runs from the same poll-timeout tick this
 * gates below, so without counting it here, a boot-only connection makes
 * srvrun_may_block_unbounded block in recvmmsg forever and the boot PTO
 * timer never gets a chance to fire (RFC 9002 6.2, handshakeloss/
 * handshakecorruption interop). */
int srvrun_has_boot_outbound(const srvrun_conn* c) {
  return srvrun_boot_probe_armed(c) && c->boot_ini_len != 0;
}

/* RFC 9002 6.2: this connection's current PTO duration in ms, scaled by
 * 2^pto_count backoff. Before any RTT sample exists, fall back to the RFC
 * 9002 6.2.2 kInitialRtt-based default (rtt_init seeds exactly that),
 * so an idle-but-just-opened connection still gets a sane (not zero)
 * deadline. */
u64 srvrun_pto_deadline_ms(const srvrun_conn* c, int pto_count) {
  pto_rtt rtt = {c->rtt.smoothed_rtt, c->rtt.rttvar};
  u64     us  = pto_duration(rtt, SRVRUN_MAX_ACK_DELAY_US, (u32)pto_count);
  return us / 1000;
}

/* RFC 9001 6.5: "SHOULD retain old read keys for no more than three times
 * the PTO" -- once that floor (measured from the rotation this connection's
 * own 1x-PTO deadline calc already knows how to size) has elapsed, drop the
 * retained old generation. A no-op before any rotation (ku_rotated_at_ms
 * stays 0 until the first one, and have_old is 0 until then too). */
void srvrun_ku_discard_stale(srvrun_conn* c, u64 now_ms) {
  u64 floor_ms;
  if (!c->s.ku.have_old) {
    return;
  }
  floor_ms = 3u * srvrun_pto_deadline_ms(c, 0);
  if (now_ms >= c->ku_rotated_at_ms + floor_ms) {
    kuswitch_discard_old(&c->s.ku);
  }
}

/* 1 if sess's oldest in-flight slice is still within its PTO window (RFC
 * 9002 6.2: probe only once send_time + PTO has elapsed) -- nothing in
 * flight counts as "not due" too, since wired_sendsess_pto_fire's own
 * nothing-in-flight case is a no-op anyway. */
int srvrun_sess_pto_due(
    const srvrun_conn* c, const wired_sendsess* sess, u64 now_ms) {
  u64 sent_ms;
  if (!wired_sendsess_oldest_sent_ms(sess, &sent_ms)) {
    return 0;
  }
  return now_ms >= sent_ms + srvrun_pto_deadline_ms(c, sess->pto_count);
}

/* Fire sess's probe if its slot is claimed and the deadline elapsed; 1 while
 * the probe budget survives, 0 once it is spent (the caller tears the whole
 * connection slot down -- shared by resp[] and wtsend slots alike). */
int srvrun_sess_pto_ok(
    const srvrun_conn* c, wired_sendsess* sess, int in_use, u64 now_ms) {
  if (!in_use || !srvrun_sess_pto_due(c, sess, now_ms)) {
    return 1;
  }
  return wired_sendsess_pto_fire(sess, SRVRUN_PTO_MAX);
}

/* Probe every in-flight response on this connection slot whose own
 * RTT-derived PTO deadline has actually elapsed (RFC 9002 6.2) -- not on
 * every poll tick regardless of RTT, which fired probes against packets
 * that were merely slow rather than lost on any link faster than the old
 * fixed SRVRUN_PTO_MS. The probe budget (SRVRUN_PTO_MAX) is a
 * connection-wide policy, not per-stream: the peer going silent means it
 * likely stopped acknowledging the whole connection, not just one stream,
 * so the first resp[] slot to exhaust its budget tears down the entire
 * connection slot rather than leaving the others to probe alone against a
 * dead peer.
 * @return 1 if every in-flight response still has probe budget, 0 if any
 *   slot's budget is spent (caller tears the connection slot down). */
int srvrun_pto_resps(srvrun_conn* c, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (!srvrun_sess_pto_ok(c, &c->resp[i].sess, c->resp[i].in_use, now_ms)) {
      return 0;
    }
  }
  return 1;
}
