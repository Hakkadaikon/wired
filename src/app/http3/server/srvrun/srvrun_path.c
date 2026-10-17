#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_path_current(
    const srvrun_cfg* cfg, const srvrun_conn* c, const pathsel_key* k);
static int srvrun_path_may_share(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const pathsel_key* k,
    int                kept);
static const peercid_entry* srvrun_path_known_cid(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k);
static const peercid_entry* srvrun_path_cid_for(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k, int kept);

/* --- RFC 9000 8.2/9: path validation and the send path ------------------
 *
 * A path is (local socket, peer address) (9.6.2). c->peer/c->tx_fd is the
 * send path; c->path holds the last validated path, two challenge slots
 * and a gated preferred-address target; c->pcid binds one peer-issued
 * connection ID to each path at its first send (9.5).
 *
 * Known hole, by design: receive routing is DCID-based (srvrun_find_slot),
 * so an off-path copy of a genuine new packet from a spoofed source still
 * moves the send path until its validation fails and the server reverts
 * (9.3.2); 9.3.3 calls that defence imperfect. A PATH_RESPONSE's arrival
 * path is never checked (8.2.2 forbids enforcing it). */

/* The path c sends on. */
pathsel_key srvrun_send_key(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return (pathsel_key){srvrun_conn_fd(cfg, c), c->peer};
}

/* The path this step's datagram arrived on. */
pathsel_key srvrun_arrival_key(const srvrun_step_ctx* ctx) {
  return (pathsel_key){srvrun_rx_fd(ctx->cfg), *ctx->peer};
}

/* The path a switch aims at: a gated preferred target, else the send
 * path. */
pathsel_key srvrun_target_key(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return c->path.gated ? c->path.target : srvrun_send_key(cfg, c);
}

int srvrun_path_is_valid(const srvrun_conn* c, const pathsel_key* k) {
  return pathsel_key_eq(&c->path.last_valid, k);
}

int srvrun_path_is_gated_target(const srvrun_conn* c, const pathsel_key* k) {
  return c->path.gated && pathsel_key_eq(&c->path.target, k);
}

/* RFC 9000 8.1: the handshake path is validated and the peer's handshake
 * ID is bound to it -- once, at the first live step. */
void srvrun_path_seed(const srvrun_cfg* cfg, srvrun_conn* c) {
  pathsel_key k = srvrun_send_key(cfg, c);
  if (c->path.seeded) {
    return;
  }
  c->path.last_valid = k;
  c->path.seeded     = 1;
  peercid_init(&c->pcid, wired_span_of(c->l.cli_scid, c->l.cli_scid_len));
  (void)peercid_bind(&c->pcid, &k);
  bytes_memcpy(c->rx_dcid, c->s.sdrv.iscid, c->s.sdrv.iscid_len);
}

/* k is the send path, the last validated one, or the gated target. */
static int srvrun_path_current(
    const srvrun_cfg* cfg, const srvrun_conn* c, const pathsel_key* k) {
  pathsel_key s = srvrun_send_key(cfg, c);
  return pathsel_key_eq(k, &s) || srvrun_path_is_valid(c, k) ||
         srvrun_path_is_gated_target(c, k);
}

/* k is tracked: current (above) or under validation. */
int srvrun_path_tracked(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k) {
  return srvrun_path_current(cfg, c, k) || pathsel_find(&c->path, k) != 0;
}

/* RFC 9000 9.5 exception: the client kept its DCID and k is on the send
 * path's local socket (a NAT rebinding). */
static int srvrun_path_may_share(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const pathsel_key* k,
    int                kept) {
  return kept && k->fd == srvrun_conn_fd(cfg, c);
}

/* The peer ID a tracked k already uses, or 0. */
static const peercid_entry* srvrun_path_known_cid(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k) {
  if (!srvrun_path_tracked(cfg, c, k)) {
    return 0;
  }
  return peercid_of(&c->pcid, k);
}

static const peercid_entry* srvrun_path_cid_for(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k, int kept) {
  const peercid_entry* e = srvrun_path_known_cid(cfg, c, k);
  pathsel_key          s = srvrun_send_key(cfg, c);
  if (e) {
    return e;
  }
  if (srvrun_path_may_share(cfg, c, k, kept)) {
    return peercid_share(&c->pcid, &s);
  }
  return peercid_bind(&c->pcid, k);
}

/* RFC 9000 9.5: the peer ID to send to k with -- the one k already uses;
 * else the send path's when the 9.5 exception holds; else an unused one;
 * else 0, and nothing may be sent on k. A client using zero-length IDs has
 * the one empty ID for every path. */
const peercid_entry* srvrun_path_cid(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k, int kept) {
  if (c->pcid.empty) {
    return &c->pcid.e[0];
  }
  return srvrun_path_cid_for(cfg, c, k, kept);
}
