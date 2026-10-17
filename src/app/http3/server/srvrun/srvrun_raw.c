#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_close_on_qpack(const srvrun_cfg* cfg, srvrun_conn* c);
static int srvrun_close_on_step_violation_rest(
    const srvrun_cfg* cfg, srvrun_conn* c);
static u32 srvrun_reset_limit(const srvrun_cfg* cfg);
static int srvrun_reset_flooded(const srvrun_cfg* cfg, const srvrun_conn* c);
static int srvrun_close_on_reset_flood(const srvrun_cfg* cfg, srvrun_conn* c);

/* The second half of srvrun_close_on_step_violation: the H3_FRAME_ERROR
 * latches, then the limits (srvrun_close_on_limits). */
/* RFC 9204 2.1.2 / 4.2 / 6: a latched QPACK violation (a second QPACK
 * stream, a bad encoder instruction, an undecodable section) closes the
 * connection with its own code. */
static int srvrun_close_on_qpack(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "qpack error";
  u16             code     = c->l.qpack_stream_violation;
  if (!code) {
    return 0;
  }
  c->l.qpack_stream_violation = 0;
  srvrun_send_app_close(cfg, c, code, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

static int srvrun_close_on_step_violation_rest(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  if (srvrun_close_on_frame_error(cfg, c)) {
    return 1;
  }
  if (srvrun_close_on_qpack(cfg, c)) {
    return 1;
  }
  return srvrun_close_on_limits(cfg, c);
}

/* RFC 9114 10.5 rapid reset: start a new fixed window (clearing the
 * srvloop reset counter) once SRVRUN_RESET_WINDOW_MS has elapsed since the
 * current one began. Runs before the step's gathering so this step's own
 * resets land in the window they belong to. */
void srvrun_roll_reset_window(srvrun_conn* c, u64 now_ms) {
  if (now_ms - c->reset_window_start_ms < SRVRUN_RESET_WINDOW_MS) {
    return;
  }
  c->reset_window_start_ms = now_ms;
  c->l.peer_reset_count    = 0;
  c->wt_sess_window_count  = 0; /* same window, SS5.2 session churn */
}

static u32 srvrun_reset_limit(const srvrun_cfg* cfg) {
  u32 v = cfg->env->max_resets_per_window;
  return v ? v : SRVRUN_MAX_RESETS_PER_WINDOW;
}

/* RFC 9114 10.5 (V-0438): 1 if this window's RESET_STREAM/STOP_SENDING
 * count passed the limit and the connection was closed over it with the
 * RFC 9114 8.1 H3_EXCESSIVE_LOAD application CONNECTION_CLOSE (the frame
 * sent stays in c->close_pl for a test to decode). */
/* 1 iff this window's resets passed the limit, or this step carried more
 * than WIRED_SRVLOOP_RESET_Q (two per tracked stream, its doc). */
static int srvrun_reset_flooded(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return c->l.peer_reset_count > srvrun_reset_limit(cfg) ||
         c->l.peer_reset_n > WIRED_SRVLOOP_RESET_Q;
}

static int srvrun_close_on_reset_flood(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "stream reset rate exceeded";
  if (!srvrun_reset_flooded(cfg, c)) {
    return 0;
  }
  srvrun_send_app_close(
      cfg, c, H3_EXCESSIVE_LOAD, wired_span_of(reason, sizeof reason - 1));
  return 1;
}

int srvrun_close_on_step_violation(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (c->l.datagram_violation) {
    srvrun_close_on_datagram_violation(cfg, c);
    return 1;
  }
  if (srvrun_close_on_reset_flood(cfg, c)) {
    return 1;
  }
  return srvrun_close_on_step_violation_rest(cfg, c);
}

/* Send this step's sealed reply, if any and if the connection is not
 * draining after a peer CONNECTION_CLOSE (RFC 9000 10.2.2). */
void srvrun_send_step_reply(
    const srvrun_cfg* cfg, srvrun_conn* c, int produced, wired_span out) {
  if (c->l.peer_closed) {
    return;
  }
  if (produced) {
    srvrun_send(cfg, c, out, "1-RTT reply sealed and sent\n");
  }
}

/* RFC 9001 6.3: a rotation just confirmed (ku.generation advanced past what
 * this step last observed) -- record when, so the retained old key's
 * 3x-PTO retention floor (srvrun_ku_discard_stale) has a start line. */
void srvrun_ku_note_rotation(srvrun_conn* c, u64 now_ms) {
  if (c->s.ku.generation == c->ku_seen_gen) {
    return;
  }
  c->ku_seen_gen      = c->s.ku.generation;
  c->ku_rotated_at_ms = now_ms;
}

/* RFC 9114 8.1 / RFC 9000 2.2: refuse every WT bidi stream this step's
 * srvloop pass found no free slot for (wt_refused) -- RESET_STREAM +
 * STOP_SENDING carrying H3_REQUEST_REJECTED ("not processed in any way", so
 * the peer may retry), never a silent drop of data the transport already
 * ACKed. Not a WebTransport application code, so a browser surfaces it as
 * a reset with no application error (draft-ietf-webtrans-http3-15 4.4). */
void srvrun_refuse_wt_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < c->l.wt_refused_n; i++) {
    srvrun_send_wt_busy_reset(
        cfg, c, c->l.wt_refused[i], srvrun_refuse_code(c, H3_REQUEST_REJECTED));
  }
  c->wt_bidi_credit_owed += c->l.wt_refused_n;
  c->l.wt_refused_n = 0;
}

/* RFC 9000 4.6/19.11: one bidi MAX_STREAMS raise for every client WT bidi
 * stream ended since the last one (wt_bidi_credit_owed). Bidi credit is
 * shared with HTTP/3 request streams and starts at the request table's
 * capacity (wired_srvloop_stream_limit); every ended stream of either kind
 * returns exactly one, so streams open at once never exceed that capacity
 * and a WT stream past the WT table is refused, not left unreadable. Then
 * the same for uni (srvrun_grant_wt_uni), for streams that ended after this
 * step's uni offer pass (peer reset, session teardown). */
void srvrun_grant_wt_streams(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  srvrun_grant_streams(
      ctx, c, srvrun_stream_limit_base(ctx), c->wt_bidi_credit_owed);
  c->wt_bidi_credit_owed = 0;
  srvrun_grant_wt_uni(ctx->cfg, c);
}

/* draft-ietf-moq-transport-19 3.1.5 / -22 6.2.2: 1 iff c is a raw-QUIC
 * connection whose handshake is confirmed and whose implicit session does
 * not exist yet (it ends only with the connection: srvrun_raw_close enters
 * the closing state, which no longer steps). */
int srvrun_raw_start_due(const srvrun_conn* c) {
  return srvrun_conn_is_raw(c) && !c->wt_active &&
         wired_server_is_confirmed(&c->s);
}

void srvrun_raw_notify(const srvrun_cfg* cfg, srvrun_conn* c) {
  wired_srvrun_env* e = cfg->env;
  if (e->raw_on_session) {
    e->raw_on_session(e->raw_session_ctx, &c->wt, c->s.sdrv.alpn_tok);
  }
}
