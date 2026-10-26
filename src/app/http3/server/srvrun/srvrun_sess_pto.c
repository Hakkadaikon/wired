#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_any_resp_active(const srvrun_conn* c);
static int  srvrun_any_wtsend_active(const srvrun_conn* c);
static int  srvrun_any_send_active(const srvrun_conn* c);
static void srvrun_send_pass(const srvrun_step_ctx* ctx, int slot);

/* RFC 9221 5.1: the app's DATAGRAM-vs-stream priority
 * (wired_srvrun_opt.datagram_first) orders the pass; whichever goes second
 * finds only the window the first left. The trailing pump is a no-op once
 * the queue drained ahead of the streams. */
static void srvrun_send_pass(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (ctx->cfg->env->datagram_first) {
    srvrun_dgring_drain(ctx->cfg, ctx->st, ctx->now_ms);
    srvrun_pump_datagram(ctx, c);
  }
  srvrun_pump_sess(ctx, slot);
  srvrun_pump_datagram(ctx, c);
}

void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (c->closing) {
    return; /* RFC 9000 10.2.1: no response, pump, or ACK */
  }
  srvrun_feed_acks(ctx, ctx->cfg, c);
  srvrun_acct_resync(c);
  cc_bbr_tick(&c->cc, srvrun_bytes_in_flight(c), ctx->now_ms);
  srvrun_apply_conn_credit_update(c);
  srvrun_apply_stream_credit_update(c);
  srvrun_apply_uni_limit_update(c);
  srvrun_reap_resps(ctx, c, slot);
  srvrun_reap_wtsends(c);
  srvrun_reannounce_stream_limit(ctx->cfg, c, srvrun_stream_limit_base(ctx));
  srvrun_reannounce_uni_stream_limit(ctx->cfg, c);
  srvrun_abort_incomplete_reqs(ctx, slot);
  srvrun_abort_frame_unexpected_reqs(ctx, slot);
  srvrun_send_continues(ctx, slot);
  srvrun_start_held_resps(ctx, slot);
  srvrun_start_done_resps(ctx, slot);
  srvrun_send_pass(ctx, slot);
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

/* 1 while this slot has anything outbound that only a poll-loop tick (not
 * this connection's own next receive) will flush: an in-flight HTTP
 * response or a broadcast DATAGRAM (dg_pending, RFC
 * 9221 5 -- queued by srvrun_broadcast_to_all/srvrun_bcast_drain_self but
 * only ever flushed from srvrun_pump_datagram, which srvrun_sess_on_step
 * reaches only when THIS connection itself next receives something). Used
 * only to decide whether the loop must keep ticking (srvrun_any_waiting);
 * NOT for the PTO probe/teardown decision (srvrun_pto_armed), which reads
 * the sent-packet record, not what is still queued. */
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
  u64 us = pto_duration(rtt, srvrun_peer_max_ack_delay_us(c), (u32)pto_count);
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
