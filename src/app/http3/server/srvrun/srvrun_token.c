#include "app/http3/server/srvrun/srvrun_impl.h"

/* RFC 9000 8.1.3: NEW_TOKEN address validation tokens, as this server
 * issues and accepts them: TOKEN_TAG_NEWTOKEN (8.1.1: told apart from a
 * Retry token by its first byte) || the newtoken wire token (unique nonce,
 * issue time, HMAC). */

static void srvrun_newtok_bind(
    const sockaddr* a, u32 version, u8 out[SRVRUN_NEWTOK_BIND]);
static int srvrun_newtok_tagged(wired_span token);
static int srvrun_newtok_confirmed_now(
    const srvrun_conn* c, const srvrun_newtok_mark* m);
static int srvrun_newtok_moved(
    const srvrun_conn* c, const srvrun_newtok_mark* m);
static int srvrun_newtok_due(const srvrun_cfg* cfg, const srvrun_conn* c);

/* RFC 9000 8.1.4: single use per token nonce. Zero static storage is an
 * empty tracker (zerortt_seen_init's state).
 * shortcut: per process -- forked srvworkers each keep their own, so a token
 * can be replayed once per worker; share it like sdrv_zerortt_share if that
 * matters. */
static zerortt_seen g_srvrun_newtok_seen;

/* RFC 9000 8.1.4: bound to the client's IP address only (a later
 * connection arrives from a fresh ephemeral port, so the port is left out),
 * and RFC 9369 5 to the QUIC version it was issued on. */
static void srvrun_newtok_bind(
    const sockaddr* a, u32 version, u8 out[SRVRUN_NEWTOK_BIND]) {
  bytes_memcpy(out, a->addr, sizeof a->addr);
  be_put_be32(out + sizeof a->addr, version);
}

usz srvrun_newtok_make(
    const sockaddr* peer, u32 version, u64 now, u8 out[SRVRUN_NEWTOK_LEN]) {
  u8 b[SRVRUN_NEWTOK_BIND];
  srvrun_newtok_bind(peer, version, b);
  out[0] = TOKEN_TAG_NEWTOKEN;
  if (!newtoken_wire_make(
          srvkeys_newtoken(), wired_span_of(b, sizeof b), now, out + 1)) {
    return 0;
  }
  return SRVRUN_NEWTOK_LEN;
}

static int srvrun_newtok_tagged(wired_span token) {
  return token.n != 0 && token.p[0] == TOKEN_TAG_NEWTOKEN;
}

/* RFC 9000 8.1.3/8.1.4, RFC 9369 5: token is one of ours, unexpired,
 * presented from the address and in the version it was issued for, and on
 * its first use. Anything else leaves the address unvalidated. */
int srvrun_newtok_ok(
    const sockaddr* peer, u32 version, wired_span token, u64 now) {
  u8         b[SRVRUN_NEWTOK_BIND];
  u64        issued_at;
  wired_span nonce;
  if (!srvrun_newtok_tagged(token)) {
    return 0;
  }
  srvrun_newtok_bind(peer, version, b);
  if (!newtoken_wire_verify(
          srvkeys_newtoken(), wired_span_of(b, sizeof b),
          wired_span_of(token.p + 1, token.n - 1), now, &issued_at, &nonce)) {
    return 0;
  }
  return zerortt_seen_check_at(&g_srvrun_newtok_seen, nonce, now);
}

/* One 1-RTT packet carrying a NEW_TOKEN frame (RFC 9000 19.7) bound to c's
 * send-path peer, or 0. */
usz srvrun_newtok_seal(srvrun_conn* c, u64 now, u8* out, usz cap) {
  u8                    tok[SRVRUN_NEWTOK_LEN], pl[SRVRUN_NEWTOK_LEN + 4];
  new_token_frame       f  = {SRVRUN_NEWTOK_LEN, tok};
  wired_obuf            ob = obuf_of(out, cap);
  wired_srvloop_send_in sin;
  if (!srvrun_newtok_make(&c->peer, sdrv_wire_version(&c->s.sdrv), now, tok)) {
    return 0;
  }
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, new_token_encode(pl, sizeof pl, &f)),
      0,
      0,
      0,
      0};
  return wired_srvloop_send_onertt(&c->s, &sin, &ob) ? ob.len : 0;
}

srvrun_newtok_mark srvrun_newtok_mark_of(const srvrun_conn* c) {
  return (srvrun_newtok_mark){
      c->path.last_valid, (u8)c->l.hs_done_sent, c->path.seeded};
}

/* RFC 9000 8.1.3: this step confirmed the handshake (HANDSHAKE_DONE went
 * out). */
static int srvrun_newtok_confirmed_now(
    const srvrun_conn* c, const srvrun_newtok_mark* m) {
  return !m->confirmed && c->l.hs_done_sent;
}

/* RFC 9000 9.3: this step validated another path than the one before (a
 * new client address). */
static int srvrun_newtok_moved(
    const srvrun_conn* c, const srvrun_newtok_mark* m) {
  return m->seeded && !pathsel_key_eq(&m->valid, &c->path.last_valid);
}

/* Owed, and the path it would go out on is the validated one (the token is
 * bound to the address it is sent to). */
static int srvrun_newtok_due(const srvrun_cfg* cfg, const srvrun_conn* c) {
  pathsel_key k = srvrun_send_key(cfg, c);
  return c->newtok_owed && srvrun_path_is_valid(c, &k);
}

/* shortcut: sent once per event, not retransmitted if lost (the token is
 * an optimisation for a later connection); queue it as a retransmittable
 * frame if loss of it shows up in practice. */
void srvrun_send_new_token(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const srvrun_newtok_mark* m) {
  u8  out[128];
  usz n;
  c->newtok_owed |=
      (u8)(srvrun_newtok_confirmed_now(c, m) | srvrun_newtok_moved(c, m));
  if (!srvrun_newtok_due(ctx->cfg, c)) {
    return;
  }
  c->newtok_owed = 0;
  n = srvrun_newtok_seal(c, wired_clock_epoch_secs(), out, sizeof out);
  if (n != 0) {
    srvrun_send(ctx->cfg, c, wired_span_of(out, n), "new token sent\n");
  }
}
