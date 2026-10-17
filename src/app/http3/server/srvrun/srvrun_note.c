#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_send_retry(const srvrun_step_ctx* ctx, const lhdr* h);
static int  srvrun_retry_token_gen_ok(
    const srvrun_step_ctx* ctx,
    wired_span             token,
    wired_span*            odcid,
    u64                    now,
    u64                    back);
static int srvrun_retry_token_ok(
    const srvrun_step_ctx* ctx, wired_span token, wired_span* odcid);
static int srvrun_retry_gate_tokened(
    const srvrun_step_ctx* ctx, const lhdr* h, wired_span* odcid);
static int srvrun_boot_pending(const srvrun_conn* c);
static int srvrun_boot_scid_match(
    const srvrun_step_ctx* ctx, usz i, wired_span dcid);

/* Build and send the stateless Retry answering h (an Initial without a
 * token): DCID = the client's SCID (RFC 9000 7.2), a fresh random SCID the
 * client will derive its next Initial keys from (RFC 9001 5.2), the wire
 * token binding the peer address to h's DCID (the true ODCID), and the
 * RFC 9001 5.8 integrity tag patched over the assembled packet. */
static void srvrun_send_retry(const srvrun_step_ctx* ctx, const lhdr* h) {
  u8  scid[8], token[RETRYTOKEN_WIRE_MAX], pkt[128];
  usz tn, n;
  srvrun_retry_prep(ctx, h, scid, token, &tn);
  if (tn == 0) {
    return;
  }
  n = srvrun_retry_pkt_build(
      h, scid, wired_span_of(token, tn), pkt, sizeof pkt);
  if (n == 0) {
    return;
  }
  srvrun_retry_finish(ctx, h, pkt, n);
}

/* Verify token under the key `back` epochs before now. */
static int srvrun_retry_token_gen_ok(
    const srvrun_step_ctx* ctx,
    wired_span             token,
    wired_span*            odcid,
    u64                    now,
    u64                    back) {
  u8 key[KEYRING_KEY];
  keyring_key(srvkeys_retry(), now, back, key);
  return retrytoken_wire_verify(
      key, wired_span_of((const u8*)ctx->peer, sizeof(*ctx->peer)), token,
      odcid);
}

/* Verify a presented token against the peer address under the current or
 * previous epoch's key; on success *odcid is the embedded original DCID (a
 * view into dg's token bytes). */
static int srvrun_retry_token_ok(
    const srvrun_step_ctx* ctx, wired_span token, wired_span* odcid) {
  u64 now = wired_clock_epoch_secs();
  return srvrun_retry_token_gen_ok(ctx, token, odcid, now, 0) ||
         srvrun_retry_token_gen_ok(ctx, token, odcid, now, 1);
}

/* h carries a token: consumed either way -- valid recovers *odcid and lets
 * the caller continue serving (0), invalid drops the datagram (1). */
static int srvrun_retry_gate_tokened(
    const srvrun_step_ctx* ctx, const lhdr* h, wired_span* odcid) {
  return !srvrun_retry_token_ok(ctx, h->token, odcid);
}

/* dg is already known to be a fresh Initial the force_retry gate applies to
 * (srvrun_retry_applies): a valid token continues serving (0, *odcid set),
 * anything else is consumed here -- a malformed header, no token (a Retry
 * goes out), or an invalid token (dropped). */
int srvrun_retry_gate(
    const srvrun_step_ctx* ctx, wired_mspan dg, wired_span* odcid) {
  lhdr h;
  if (!lhdr_parse(wired_span_of(dg.p, dg.n), 1, &h)) {
    return 1;
  }
  if (h.token.n != 0) {
    return srvrun_retry_gate_tokened(ctx, &h, odcid);
  }
  srvrun_send_retry(ctx, &h);
  return 1;
}

/* Stash the token-recovered ODCID on the freshly claimed slot so the accept
 * path advertises it (srvrun_slot_id -> srvboot_tp_odcid). */
void srvrun_note_retry_odcid(srvrun_conn* c, wired_span odcid) {
  if (odcid.n == 0 || odcid.n > WIRED_MAX_CID_LEN) {
    return;
  }
  bytes_memcpy(c->retry_odcid, odcid.p, odcid.n);
  c->retry_odcid_len = (u8)odcid.n;
}

/* Answer an unsupported-version datagram with Version Negotiation, straight
 * to the sender — no connection slot is involved (RFC 9000 5.2.2). Returns 1
 * when the datagram was consumed this way. */
int srvrun_vneg(const srvrun_step_ctx* ctx, wired_mspan dg) {
  u8  vn[64];
  usz n = wired_srvboot_vneg(wired_span_of(dg.p, dg.n), vn, sizeof vn);
  if (!n) {
    return 0;
  }
  srvrun_tx(ctx->cfg, srvrun_rx_fd(ctx->cfg), ctx->peer, wired_span_of(vn, n));
  return 1;
}

/* 1 while slot i is a claimed boot that has absorbed something but is not
 * up yet -- the only state whose scid a switched client DCID may name. */
static int srvrun_boot_pending(const srvrun_conn* c) {
  return !c->up && c->boot.any;
}

/* 1 if slot i is a still-pending boot whose own scid equals dcid. */
static int srvrun_boot_scid_match(
    const srvrun_step_ctx* ctx, usz i, wired_span dcid) {
  const srvrun_conn* c = &ctx->st->conns[i];
  if (!srvrun_boot_pending(c)) {
    return 0;
  }
  if (dcid.n != ctx->cfg->id->scid_len) {
    return 0;
  }
  return ct_diffn(c->scid, dcid.p, dcid.n) == 0;
}

/* The pending boot slot whose own scid is dcid, or -1: after a
 * partial-ClientHello ack the client switches its DCID to that scid
 * (RFC 9000 7.2) while the routing entry still keys the ODCID -- without
 * this, the switched retransmits claimed a competing slot with a
 * different initial_source_connection_id. */
int srvrun_find_boot_scid(const srvrun_step_ctx* ctx, wired_span dcid) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (srvrun_boot_scid_match(ctx, i, dcid)) {
      return (int)i;
    }
  }
  return -1;
}
