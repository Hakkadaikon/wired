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
static int srvrun_token_retry_verdict(
    const srvrun_step_ctx* ctx,
    const lhdr*            h,
    wired_span*            odcid,
    int*                   validated);
static int srvrun_token_other_verdict(
    const srvrun_step_ctx* ctx, const lhdr* h, u32 version, int* validated);
static int srvrun_token_act(
    const srvrun_step_ctx* ctx, const lhdr* h, wired_mspan dg, int verdict);
static int srvrun_boot_pending(const srvrun_conn* c);
static int srvrun_boot_scid_match(
    const srvrun_step_ctx* ctx, usz i, wired_span dcid);

/* Build and send the stateless Retry answering h (an Initial without a
 * token): DCID = the client's SCID (RFC 9000 7.2), a fresh random SCID the
 * client will derive its next Initial keys from (RFC 9001 5.2), the wire
 * token binding the peer address to h's DCID (the true ODCID), and the
 * RFC 9001 5.8 integrity tag patched over the assembled packet. */
static void srvrun_send_retry(const srvrun_step_ctx* ctx, const lhdr* h) {
  u8  scid[8], token[SRVRUN_RETRY_TOKEN_MAX], pkt[128];
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

/* RFC 9000 8.1.2: a Retry token (TOKEN_TAG_RETRY first byte) validates
 * the address and recovers *odcid, or -- invalid, so the client "will not
 * accept another Retry token" -- closes with INVALID_TOKEN. */
static int srvrun_token_retry_verdict(
    const srvrun_step_ctx* ctx,
    const lhdr*            h,
    wired_span*            odcid,
    int*                   validated) {
  wired_span body = wired_span_of(h->token.p + 1, h->token.n - 1);
  if (!srvrun_retry_token_ok(ctx, body, odcid)) {
    return SRVRUN_TOK_CLOSE;
  }
  *validated = 1;
  return SRVRUN_TOK_SERVE;
}

/* RFC 9000 8.1.3: no token, or one that is not a Retry token: a valid
 * NEW_TOKEN token validates the address; any other "proceed[s] as if the
 * client did not have a validated address, including potentially sending a
 * Retry" -- the Retry under force_retry. */
static int srvrun_token_other_verdict(
    const srvrun_step_ctx* ctx, const lhdr* h, u32 version, int* validated) {
  *validated =
      srvrun_newtok_ok(ctx->peer, version, h->token, wired_clock_epoch_secs());
  return *validated || !ctx->cfg->force_retry ? SRVRUN_TOK_SERVE
                                              : SRVRUN_TOK_RETRY;
}

/* What a fresh Initial with long header h (sent in version) gets for its
 * token (RFC 9000 8.1.1: the two kinds are told apart by the tag byte). */
int srvrun_token_verdict(
    const srvrun_step_ctx* ctx,
    const lhdr*            h,
    u32                    version,
    wired_span*            odcid,
    int*                   validated) {
  if (token_is_retry(h->token.p, h->token.n)) {
    return srvrun_token_retry_verdict(ctx, h, odcid, validated);
  }
  return srvrun_token_other_verdict(ctx, h, version, validated);
}

/* Carry out verdict: 0 serves dg, 1 consumed it (a Retry or a close went
 * out). */
static int srvrun_token_act(
    const srvrun_step_ctx* ctx, const lhdr* h, wired_mspan dg, int verdict) {
  if (verdict == SRVRUN_TOK_SERVE) {
    return 0;
  }
  if (verdict == SRVRUN_TOK_RETRY) {
    srvrun_send_retry(ctx, h);
    return 1;
  }
  srvrun_send_initial_close(ctx, dg, ERR_INVALID_TOKEN);
  return 1;
}

/* dg is already known to be a fresh Initial (srvrun_retry_applies): serve
 * it (0; *odcid / *validated set from a valid token) or consume it (1).
 * A malformed header is dropped under force_retry and otherwise left to
 * the ordinary routing path. */
int srvrun_retry_gate(
    const srvrun_step_ctx* ctx,
    wired_mspan            dg,
    wired_span*            odcid,
    int*                   validated) {
  lhdr h;
  if (!lhdr_parse(wired_span_of(dg.p, dg.n), 1, &h)) {
    return ctx->cfg->force_retry;
  }
  return srvrun_token_act(
      ctx, &h, dg,
      srvrun_token_verdict(ctx, &h, be_get_be32(dg.p + 1), odcid, validated));
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
