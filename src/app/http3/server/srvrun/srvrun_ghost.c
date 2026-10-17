#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_is_refusable_new_conn(wired_span dcid, wired_mspan dg);
static int srvrun_seal_new_conn_refusal(
    wired_span dg, const u8 scid[8], wired_obuf* out);
static int srvrun_retry_wanted(const srvrun_step_ctx* ctx, wired_mspan dg);
static int srvrun_ghost_hit(const srvrun_ghost* g, wired_span dcid, u64 now_ms);

/* srvrun_route plus the full-table eviction fallback (srvrun_evict_for_
 * initial). Routing to an existing slot always wins -- a retransmitted
 * Initial must reach its own connection, never trigger an eviction. */
int srvrun_route_or_evict(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  int slot = srvrun_route(ctx, dcid, dg);
  if (slot >= 0) {
    return slot;
  }
  return srvrun_evict_for_initial(
      ctx, dcid, wired_srvboot_is_initial(dg.p, dg.n));
}

/* RFC 9000 5.2.2: whether a datagram that matched no slot and could not
 * claim a fresh one is a genuine new-connection attempt being turned away
 * (graceful shutdown or a full conntable) rather than something that was
 * never eligible to open one in the first place (a malformed/absent DCID or
 * a non-Initial packet) -- only the former deserves a refusal reply. */
static int srvrun_is_refusable_new_conn(wired_span dcid, wired_mspan dg) {
  return dcid.p != 0 && wired_srvboot_is_initial(dg.p, dg.n);
}

/* RFC 9000 5.2.2/19.19: build a transport CONNECTION_CLOSE(CONNECTION_REFUSED)
 * as an unpadded server Initial addressed to the client's own DCID/SCID, using
 * Initial keys derived from dcid (no live connection or session state is
 * needed -- Initial keys come from the DCID alone, RFC 9001 5.2). Returns 1
 * with out->len set, 0 on a malformed header or overflow. */
static int srvrun_seal_new_conn_refusal(
    wired_span dg, const u8 scid[8], wired_obuf* out) {
  lhdr             h;
  u8               fr[8];
  usz              fn;
  conn_close_frame cc = {0, ERR_CONNECTION_REFUSED, 0, 0, 0};
  srvwire_seal_in  wi;
  if (!lhdr_parse(dg, 1, &h)) {
    return 0;
  }
  fn = frame_put_conn_close(fr, sizeof fr, &cc);
  if (!fn) {
    return 0;
  }
  /* refused in the version the client's own Initial used (its header's
   * Version field -- lhdr_parse already proved dg holds one) */
  wi = (srvwire_seal_in){h.dcid,
                         h.scid,
                         wired_span_of(scid, 8),
                         0,
                         -1,
                         wired_span_of(fr, fn),
                         0,
                         0,
                         0,
                         0,
                         be_get_be32(dg.p + 1)};
  return srvwire_seal_initial_frames_lean(&wi, out);
}

/* Seal and send the refusal above, addressed to ctx->peer. A server-chosen
 * SCID of zero length is fine (RFC 9000 7.2 allows an empty CID); this
 * connection ends immediately after, so no routing table entry is needed
 * for it. */
void srvrun_send_new_conn_refusal(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  u8         out[128];
  u8         scid[8] = {0};
  wired_obuf ob      = obuf_of(out, sizeof out);
  if (!srvrun_is_refusable_new_conn(dcid, dg)) {
    return;
  }
  if (!srvrun_seal_new_conn_refusal(wired_span_of(dg.p, dg.n), scid, &ob)) {
    return;
  }
  srvrun_tx(
      ctx->cfg, srvrun_rx_fd(ctx->cfg), ctx->peer, wired_span_of(out, ob.len));
  wired_log_str("conn refused: table full\n");
}

/* 1 if force_retry is on and dg is a fresh Initial (the gate's precondition
 * before any slot lookup). */
static int srvrun_retry_wanted(const srvrun_step_ctx* ctx, wired_mspan dg) {
  return ctx->cfg->force_retry && wired_srvboot_is_initial(dg.p, dg.n);
}

/* The retry gate applies only to an Initial whose DCID matches no live
 * slot: a claimed slot's own retransmits already passed validation once,
 * and a post-Retry Initial routes by the token path instead. */
int srvrun_retry_applies(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  if (!srvrun_retry_wanted(ctx, dg)) {
    return 0;
  }
  if (srvrun_find_slot(ctx, dcid) >= 0) {
    return 0;
  }
  return srvrun_find_boot_scid(ctx, dcid) < 0;
}

/* 1 if the force_retry gate consumed dg (a Retry went out, or an invalid
 * token was dropped) -- the caller stops here either way. */
int srvrun_retry_consumed(
    const srvrun_step_ctx* ctx,
    wired_span             dcid,
    wired_mspan            dg,
    wired_span*            odcid) {
  if (!srvrun_retry_applies(ctx, dcid, dg)) {
    return 0;
  }
  return srvrun_retry_gate(ctx, dg, odcid);
}

/* 1 if dcid names a freshly closed connection still inside its remembered
 * window (srvrun_ghost) -- its stragglers are swallowed, not reset. */
static int srvrun_ghost_hit(
    const srvrun_ghost* g, wired_span dcid, u64 now_ms) {
  return now_ms < g->until_ms && g->len == dcid.n &&
         ct_diffn(g->scid, dcid.p, dcid.n) == 0;
}

int srvrun_ghost_match(const srvrun_step_ctx* ctx, wired_span dcid) {
  const wired_srvrun_env* env = ctx->cfg->env;
  for (usz i = 0; i < SRVRUN_GHOST_SLOTS; i++) {
    if (srvrun_ghost_hit(&env->ghosts[i], dcid, ctx->now_ms)) {
      return 1;
    }
  }
  return 0;
}
