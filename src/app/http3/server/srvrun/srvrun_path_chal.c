#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_send_to(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const pathsel_key* k,
    wired_span         pkt);

/* The send path becomes k; every later packet carries k's peer ID (RFC
 * 9000 9.5), the connection's default from now on. */
void srvrun_path_move(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k) {
  pathsel_key          to = *k;
  const peercid_entry* e;
  c->peer  = to.peer;
  c->tx_fd = to.fd;
  e        = srvrun_path_cid(cfg, c, &to, 0);
  /* ponytail: with no ID left the old one stays; the peer must issue more */
  if (!e) return;
  bytes_memcpy(c->l.cli_scid, e->cid, e->len);
  c->l.cli_scid_len = e->len;
}

/* One sealed path packet to k, outside the send path's GSO stage. */
static void srvrun_send_to(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const pathsel_key* k,
    wired_span         pkt) {
  if (c->closing) return;
  srvrun_tx(cfg, k->fd, &k->peer, pkt);
  srvrun_qlog_sent(cfg, c, pkt.n);
  g_srvrun_send_count++;
}

/* n PATH_CHALLENGE or PATH_RESPONSE frames (data[0..n)) to k under its
 * peer ID e. */
void srvrun_path_send(
    const srvrun_cfg*    cfg,
    srvrun_conn*         c,
    const pathsel_key*   k,
    const peercid_entry* e,
    u8                   type,
    const u8*            data,
    usz                  n) {
  u8         out[MIN_INITIAL_DATAGRAM];
  wired_obuf ob   = obuf_of(out, sizeof out);
  wired_span dcid = wired_span_of(e->cid, e->len);
  if (!srvrun_seal_path_frames(c, dcid, type, data, n, &ob)) return;
  srvrun_send_to(cfg, c, k, wired_span_of(out, ob.len));
}

/* RFC 9000 8.2.1: send slot s's path a PATH_CHALLENGE with fresh data under
 * its peer ID. Without random data or an ID the slot is freed and nothing
 * is sent. */
void srvrun_path_challenge(
    const srvrun_cfg* cfg, srvrun_conn* c, pathsel_slot* s, u64 now) {
  const peercid_entry* e = srvrun_path_cid(cfg, c, &s->key, 0);
  bytes_memcpy(s->prev, s->data, PATH_DATA);
  if (!e || !srvrun_gen_path_challenge(s->data)) {
    s->in_use = 0;
    return;
  }
  s->last_ms = now;
  srvrun_path_send(cfg, c, &s->key, e, FRAME_PATH_CHALLENGE, s->data, 1);
}

/* Start a validation in slot s (0 = no slot: nothing to do).
 * ponytail: re-arming a path (e.g. as the old path of a second move) starts
 * a fresh challenge; a late response to the one before is not matched and
 * the path validates on the next one. */
void srvrun_path_arm(
    const srvrun_cfg* cfg, srvrun_conn* c, pathsel_slot* s, u64 now) {
  if (!s) return;
  s->first_ms = now;
  s->tries    = 0;
  srvrun_path_challenge(cfg, c, s, now);
}

/* RFC 9000 9.3: challenge the new target unless it is validated or already
 * under validation; the path being left keeps its slot. */
void srvrun_path_chal_new(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     to,
    const pathsel_key*     from) {
  if (srvrun_path_is_valid(c, to) || pathsel_find(&c->path, to)) return;
  srvrun_path_arm(ctx->cfg, c, pathsel_claim(&c->path, to, from), ctx->now_ms);
}

/* RFC 9000 9.3.3: challenge the path non-probing packets were being sent
 * on, when it is not the new target. */
void srvrun_path_chal_old(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    const pathsel_key*     from,
    const pathsel_key*     to) {
  if (pathsel_key_eq(from, to)) return;
  srvrun_path_arm(ctx->cfg, c, pathsel_claim(&c->path, from, to), ctx->now_ms);
}

/* RFC 9000 9.6.2: the preferred-address socket carries non-probing packets
 * only once its path is validated. */
int srvrun_path_gates(
    const srvrun_cfg* cfg, const srvrun_conn* c, const pathsel_key* k) {
  i64 pref = cfg->env->pref_fd;
  return pref && k->fd == pref && !srvrun_path_is_valid(c, k);
}
