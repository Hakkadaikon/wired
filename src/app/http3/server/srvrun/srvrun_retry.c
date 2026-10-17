#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_resp_rows_clear(srvrun_conn* c);
static void srvrun_conn_cc_init(const srvrun_cfg* cfg, srvrun_conn* c);
static void srvrun_conn_fresh(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot);

/* Mark every resp[] slot as holding no wired_srvbigbuf row (-1; 0 is a real
 * row index -- see the caller's note). */
static void srvrun_resp_rows_clear(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) c->resp[i].bigbuf_row = -1;
}

/* Start c's congestion control, ECN, HyStart, RTT and PMTU state fresh. */
static void srvrun_conn_cc_init(const srvrun_cfg* cfg, srvrun_conn* c) {
  cc_init_algo(&c->cc, srvrun_cc_algo(cfg));
  ecn_track_init(&c->ecn);
  hystart_init(&c->hs);
  rtt_init(&c->rtt);
  pmtu_init(&c->pmtu);
}

/* Wipe the just-claimed slot c (index slot) for a new connection from
 * ctx->peer, bumping its generation. */
static void srvrun_conn_fresh(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  u32 gen          = c->gen + 1;
  *c               = (srvrun_conn){0};
  c->gen           = gen;
  c->peer          = *ctx->peer;
  c->boot_claim_ms = ctx->now_ms;
  c->qlog_slot     = (u64)slot;
  c->l.qlog_path   = ctx->cfg->qlog_path;
  c->l.qlog_group  = (u64)slot;
  srvrun_conn_cc_init(ctx->cfg, c);
  /* the {0} slot wipe above left every resp[].bigbuf_row at 0 -- a VALID
   * pool row index. The teardown sweep (srvrun_free_bigbuf_rows) would then
   * release row 0 on behalf of responses that never claimed anything,
   * freeing it out from under another connection mid-delivery. -1 = "holds
   * no row", matching srvrun_resp_claim's own reset. */
  srvrun_resp_rows_clear(c);
  c->pmtu_probe_pn = SRVRUN_PMTU_NO_PROBE;
  c->tx_fd         = srvrun_rx_fd(ctx->cfg);
}

/* Claim and initialize a fresh slot for dcid: record the peer, and generate
 * this slot's own scid (never cfg->id's fixed one — every slot sharing it
 * would collapse conntable's routing back to a single slot). Returns the slot
 * index, or -1 if claiming fails or scid generation fails (in which case the
 * claimed slot is freed again rather than run with an all-zero scid). */
int srvrun_open_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  int          slot = srvrun_claim_slot(ctx, dcid, is_initial);
  srvrun_conn* c;
  if (slot < 0) return -1;
  c = &ctx->st->conns[slot];
  srvrun_conn_fresh(ctx, c, slot);
  if (srvrun_issue_cid(ctx->cfg, c->scid, ctx->cfg->id->scid_len)) {
    srvrun_issue_spare_cid(ctx->cfg, c);
    return slot;
  }
  conntable_remove(ctx->st->table, WIRED_CONNTABLE_CAP, slot);
  return -1;
}

/* Drive one received datagram: resolve it to a connection slot by DCID (a
 * fresh slot only for an unrecognized DCID on a new Initial, RFC 9000 5.1/7)
 * and serve it there. Silently drops a datagram that matches no slot and
 * cannot claim or initialize a new one. */
/* RFC 9000 8.1.2 forced address validation (the interop retry testcase):
 * Retry-token HMAC keys derive from srvkeys_retry, a per-process CSPRNG
 * seed; the key rotates every KEYRING_PERIOD_SECS and the previous one
 * still verifies (keyring.h). */

/* Seal DCID=h->scid/SCID=scid/token into pkt with a garbage tag; the caller
 * patches the real RFC 9001 5.8 tag in afterward. Returns bytes written, or
 * 0 on overflow. */
usz srvrun_retry_pkt_build(
    const lhdr* h, const u8 scid[8], wired_span token, u8* pkt, usz cap) {
  retry_desc d = {1, h->scid, wired_span_of(scid, 8), token, pkt};
  return retry_build(pkt, cap, &d);
}

/* scid + wire token for the Retry answering h, or 0 tn on RNG/overflow
 * failure. */
void srvrun_retry_prep(
    const srvrun_step_ctx* ctx,
    const lhdr*            h,
    u8                     scid[8],
    u8                     token[RETRYTOKEN_WIRE_MAX],
    usz*                   tn) {
  *tn = 0;
  if (!cid_generate(scid, 8)) return;
  u8 key[KEYRING_KEY];
  keyring_key(srvkeys_retry(), wired_clock_epoch_secs(), 0, key);
  *tn = retrytoken_wire_make(
      key, wired_span_of((const u8*)ctx->peer, sizeof(*ctx->peer)), h->dcid,
      token);
}

/* Assemble the Retry with its real integrity tag and send it: pkt already
 * carries a garbage tag (srvrun_retry_pkt_build); patch in the RFC 9001 5.8
 * tag computed over everything before it. */
void srvrun_retry_finish(
    const srvrun_step_ctx* ctx, const lhdr* h, u8* pkt, usz n) {
  retry_tag(
      h->dcid, wired_span_of(pkt, n - RETRY_TAG_LEN), pkt + n - RETRY_TAG_LEN);
  srvrun_tx(ctx->cfg, srvrun_rx_fd(ctx->cfg), ctx->peer, wired_span_of(pkt, n));
}
