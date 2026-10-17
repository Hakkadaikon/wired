#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_send_max_streams(
    const srvrun_cfg* cfg, srvrun_conn* c, int uni, u64 value);
static int srvrun_grant_retry_due(const srvrun_conn* c, u64 now_ms);
static int wt_any_bidi_slot_in_use(const srvrun_conn* c);
static int wt_any_uni_slot_in_use(const srvrun_conn* c);

static void srvrun_send_max_streams(
    const srvrun_cfg* cfg, srvrun_conn* c, int uni, u64 value) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_max_streams(c, uni, value, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "MAX_STREAMS sent\n");
  if (uni)
    c->uni_stream_limit_advertised = value;
  else
    c->stream_limit_advertised = value;
}

/* RFC 9000 4.6/19.11: raise the advertised bidi stream limit by n to match
 * the receive-side capacity the srvloop slots a reap pass (srvrun_
 * reap_resps) just released freed up -- keeps "limit advertised to the
 * client" in lockstep with "requests this SDK can actually reassemble at
 * once" (WIRED_SRVLOOP_MAX_STREAMS) instead of promising room the
 * fixed-size slot table cannot back. One MAX_STREAMS frame carries the
 * whole batch (n released slots used to cost n separate datagrams). base
 * is the limit already in force (the connection's transport-parameter
 * default the first time this fires, srvrun_conn.stream_limit_advertised
 * after that). Keeping this invariant (raise == releases) means the
 * currently-advertised limit is always derivable, so a later
 * STREAMS_BLOCKED (srvrun_reannounce_stream_limit) never needs to compute
 * anything new -- it just repeats this same value. */
void srvrun_grant_streams(
    const srvrun_step_ctx* ctx, srvrun_conn* c, u64 base, usz n) {
  u64 current = c->stream_limit_advertised ? c->stream_limit_advertised : base;
  if (!n) return;
  srvrun_send_max_streams(ctx->cfg, c, 0, current + n);
  /* RFC 9000 4.6: the frame is fire-and-forget -- arm the bounded
   * re-announce (see srvrun_conn.grant_retry_ms's doc). */
  c->grant_retries  = 2;
  c->grant_retry_ms = ctx->now_ms + srvrun_pto_deadline_ms(c, 0);
}

/* Re-announce the bidi limit in force at each armed deadline until the
 * bounded retry budget is spent -- cumulative MAX_STREAMS makes the repeat
 * idempotent at the client. */
/* A re-announcement is owed and due on c -- and c is still a live
 * connection: a freed slot keeps its counters until reclaimed, and RFC 9000
 * 10.2 lets nothing more go out on a connection that has ended. */
static int srvrun_grant_retry_due(const srvrun_conn* c, u64 now_ms) {
  return c->up && c->grant_retries && now_ms >= c->grant_retry_ms;
}

void srvrun_grant_retry_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!srvrun_grant_retry_due(c, ctx->now_ms)) return;
  c->grant_retries--;
  c->grant_retry_ms = ctx->now_ms + srvrun_pto_deadline_ms(c, 0);
  srvrun_send_max_streams(ctx->cfg, c, 0, c->stream_limit_advertised);
}

/* srvrun_grant_streams' uni mirror: raise the advertised UNI stream limit by
 * n (one per WT uni reassembly slot released this pass), from the slot-
 * backed initial advertisement (wired_srvloop_uni_stream_limit -- the TP
 * and this base must agree, RFC 9000 4.6's capacity lockstep). */
void srvrun_grant_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c, usz n) {
  u64 current = c->uni_stream_limit_advertised
                    ? c->uni_stream_limit_advertised
                    : wired_srvloop_uni_stream_limit();
  if (n) srvrun_send_max_streams(cfg, c, 1, current + (u64)n);
}

/* RFC 9000 4.6: "An endpoint that receives a STREAMS_BLOCKED frame SHOULD
 * send a MAX_STREAMS frame if it is willing to increase the limit." This
 * SDK's limit only ever advances in lockstep with real receive capacity
 * (srvrun_grant_streams, one batched raise per reap pass), so there is
 * nothing new to compute here -- just resend the limit already in force
 * (or the transport-parameter default if nothing has been granted yet) in
 * case the peer's own copy of it was lost. Never trusts the peer's own
 * claimed limit in the STREAMS_BLOCKED frame (the value itself is
 * not even latched, see wired_srvloop.streams_blocked_seen_flag's doc). */
void srvrun_reannounce_stream_limit(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 base) {
  if (!c->l.streams_blocked_seen_flag) return;
  c->l.streams_blocked_seen_flag = 0;
  srvrun_send_max_streams(
      cfg, c, 0,
      c->stream_limit_advertised ? c->stream_limit_advertised : base);
}

/* srvrun_reannounce_stream_limit's uni mirror: a UNI STREAMS_BLOCKED
 * sighting re-sends the uni limit already in force (or the transport-
 * parameter default before any uni release raised it). */
void srvrun_reannounce_uni_stream_limit(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!c->l.streams_blocked_uni_seen_flag) return;
  c->l.streams_blocked_uni_seen_flag = 0;
  srvrun_send_max_streams(
      cfg, c, 1,
      c->uni_stream_limit_advertised ? c->uni_stream_limit_advertised
                                     : wired_srvloop_uni_stream_limit());
}

/* 1 if any WT bidi or uni slot is currently in use -- srvrun_grant_conn_
 * credit's own gate: a connection with no WT reassembly activity at all has
 * nothing this MAX_DATA raise is for (the server's own initial_max_data
 * transport parameter, server_tp.c, already covers ordinary request/response
 * traffic), so sending one unconditionally every step would put an unasked-
 * for frame on the wire of every plain HTTP/3 connection too. */
static int wt_any_bidi_slot_in_use(const srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (c->l.wt_streams[i].in_use) return 1;
  return 0;
}

static int wt_any_uni_slot_in_use(const srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (c->l.wt_uni_streams[i].in_use) return 1;
  return 0;
}

int srvrun_wt_any_slot_in_use(const srvrun_conn* c) {
  return wt_any_bidi_slot_in_use(c) || wt_any_uni_slot_in_use(c);
}
