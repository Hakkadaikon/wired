#include "app/http3/server/srvrun/srvrun_impl.h"

/* #200 / wired_wt_on_stream_credit: remember a server-initiated WT open
 * refused for lack of credit, and tell the app once the same open would
 * pass every gate it failed (draft-ietf-webtrans-http3-16 5.3/5.6.2
 * WT_MAX_STREAMS/WT_MAX_DATA, RFC 9000 4.6 MAX_STREAMS, the send-slot share).
 * Polled per step rather than hooked into each credit source, so a raise by
 * any of them -- or a freed send slot -- is seen the same way. */

void srvrun_wt_credit_arm(srvrun_conn* c, int sidx, int bidi, usz len) {
  if (sidx < 0) {
    return;
  }
  c->wtx.credit_wait[sidx] = (u8)(bidi + 1);
  c->wtx.credit_len[sidx]  = len;
}

/* RFC 9000 4.6: only a uni open also needs the peer's QUIC uni-stream
 * grant; checked side-effect free (srvrun_wt_uni_grant_ok latches
 * STREAMS_BLOCKED). */
static int srvrun_wt_credit_quic_ok(const srvrun_conn* c, int bidi) {
  return bidi || srvrun_uni_open_allowed(c);
}

/* The refused open of slot sidx would now pass the same gates. */
static int srvrun_wt_credit_ok(srvrun_conn* c, int sidx) {
  int        bidi = c->wtx.credit_wait[sidx] - 1;
  wired_span want = {0, c->wtx.credit_len[sidx]};
  return srvrun_wt_open_flow_ok(sidx, srvrun_wt_slot(c, sidx), bidi, want) &&
         srvrun_wt_open_share_ok(c, sidx) && srvrun_wt_credit_quic_ok(c, bidi);
}

static int srvrun_wt_credit_due(srvrun_conn* c, int sidx) {
  return c->wtx.credit_wait[sidx] && srvrun_wt_is_active(c, sidx) &&
         srvrun_wt_credit_ok(c, sidx);
}

/* Cleared before the call, so an open the app retries from inside it that is
 * refused again re-arms the wait. */
static void srvrun_wt_credit_fire(
    const wired_srvrun_env* env, srvrun_conn* c, int sidx) {
  if (!srvrun_wt_credit_due(c, sidx)) {
    return;
  }
  c->wtx.credit_wait[sidx] = 0;
  if (env->wt_on_stream_credit) {
    env->wt_on_stream_credit(
        env->wt_stream_credit_ctx, srvrun_wt_slot(c, sidx));
  }
}

void srvrun_wt_credit_poll(const wired_srvrun_env* env, srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    srvrun_wt_credit_fire(env, c, i);
  }
}
