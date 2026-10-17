#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_rebind_allowed(
    const srvrun_step_ctx* ctx, const srvrun_conn* c);
static usz srvrun_path_challenge_take(srvrun_conn* c);
static int srvrun_path_answer(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     a,
    usz                    n,
    int                    kept);
static void srvrun_path_probe_fresh(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     a,
    usz                    n,
    int                    kept);

/* RFC 9000 9.3: the arrival path becomes the target, the new path and the
 * path left are challenged, and the send path follows unless the target is
 * a gated preferred path. With no peer ID for the new path, nothing
 * happens at all (9.5). */
void srvrun_path_switch(const srvrun_step_ctx* ctx, srvrun_conn* c, int kept) {
  pathsel_key to = srvrun_arrival_key(ctx), from = srvrun_send_key(ctx->cfg, c);
  if (!srvrun_path_cid(ctx->cfg, c, &to, kept)) {
    return;
  }
  srvrun_path_chal_new(ctx, c, &to, &from);
  srvrun_path_chal_old(ctx, c, &from, &to);
  c->path.target = to;
  c->path.gated  = (u8)srvrun_path_gates(ctx->cfg, c, &to);
  if (!c->path.gated) {
    srvrun_path_move(ctx->cfg, c, &to);
  }
}

/* RFC 9000 9.6.2: this connection sends from the preferred-address socket
 * and the datagram arrived on another one. The server SHOULD drop newer
 * packets received on the old address (srvloop's drop_newer) and MAY
 * process delayed ones -- which then never move the path back. */
int srvrun_path_reverts(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  i64 pref = ctx->cfg->env->pref_fd;
  return pref && c->tx_fd == pref && srvrun_rx_fd(ctx->cfg) != pref;
}

/* A switch is allowed: confirmed, not a suppressed old-path straggler, and
 * the arrival path is not already the target. */
static int srvrun_rebind_allowed(
    const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  pathsel_key a = srvrun_arrival_key(ctx), t = srvrun_target_key(ctx->cfg, c);
  if (srvrun_awaiting_confirm(c) || srvrun_path_reverts(ctx, c)) {
    return 0;
  }
  return !pathsel_key_eq(&a, &t);
}

/* RFC 9000 9.3: only a live (not replayed) short-header packet that is
 * non-probing and numbered above every earlier non-probing one
 * (srvloop's step_np_new) may move the target. */
int srvrun_rebind_due(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  if (!c->l.step_np_new || c->replay) {
    return 0;
  }
  return srvrun_rebind_allowed(ctx, c);
}

/* The latched PATH_CHALLENGEs to answer, consumed: none on a closing or
 * peer-closed connection (RFC 9000 10.2). */
static usz srvrun_path_challenge_take(srvrun_conn* c) {
  usz n                    = c->l.path_challenge_rx_n;
  c->l.path_challenge_rx_n = 0;
  return c->closing || c->l.peer_closed ? 0 : n;
}

/* RFC 9000 8.2.2: answer this step's n PATH_CHALLENGEs on their arrival
 * path, one PATH_RESPONSE each, in the receive step and padded like a
 * challenge (8.2.1) -- under that path's peer ID, and not at all without
 * one (9.5). 1 if answered. */
static int srvrun_path_answer(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     a,
    usz                    n,
    int                    kept) {
  const peercid_entry* e = srvrun_path_cid(ctx->cfg, c, a, kept);
  if (!e) {
    return 0;
  }
  srvrun_path_send(
      ctx->cfg, c, a, e, FRAME_PATH_RESPONSE,
      &c->l.path_challenge_rx_data[0][0], n);
  return 1;
}

/* RFC 9000 9.6.3: a probe from an untracked path is answered and its
 * validation started only when a slot is free (never evicting); without
 * one it is ignored, so no peer ID is bound to a path dropped at once. */
static void srvrun_path_probe_fresh(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     a,
    usz                    n,
    int                    kept) {
  pathsel_slot* s = pathsel_claim_free(&c->path, a);
  if (!s) {
    return;
  }
  /* bind the path's peer ID (with the 9.5 exception), then challenge before
   * answering: the first datagram on the new path carries the
   * PATH_CHALLENGE; a path without a peer ID frees the slot, unanswered */
  s->in_use = srvrun_path_cid(ctx->cfg, c, a, kept) != 0;
  if (!s->in_use) {
    return;
  }
  srvrun_path_arm(ctx->cfg, c, s, ctx->now_ms);
  (void)srvrun_path_answer(ctx, c, a, n, kept);
}

void srvrun_path_probe(const srvrun_step_ctx* ctx, srvrun_conn* c, int kept) {
  pathsel_key a = srvrun_arrival_key(ctx);
  usz         n = srvrun_path_challenge_take(c);
  if (!n) {
    return;
  }
  if (srvrun_path_tracked(ctx->cfg, c, &a)) {
    (void)srvrun_path_answer(ctx, c, &a, n, kept);
    return;
  }
  srvrun_path_probe_fresh(ctx, c, &a, n, kept);
}
