#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_resend_flight_on_hs_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int booting, wired_mspan dg);
static int srvrun_xdp_core_routing(const srvrun_cfg* cfg);

/* One due boot retransmission round: the fresh keepalive once the peer
 * provably finished, the cached flight otherwise -- and if the keepalive
 * could not go out (no 1-RTT key yet, budget), the plain replay, so this
 * path is never worse than the replay alone. */
int srvrun_boot_probe_or_replay(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (c->peer_at_onertt && srvrun_send_boot_probe(ctx, c)) {
    return 1;
  }
  return srvrun_resend_boot_flight(ctx, c);
}

static void srvrun_resend_flight_on_hs_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int booting, wired_mspan dg) {
  if (srvrun_hs_probe_pending(c, booting, dg)) {
    srvrun_boot_probe_or_replay(ctx, c);
  }
}

/* Confirmation landed this very step (booting = the pre-step state):
 * replay the datagrams held while processing them was forbidden
 * (srvrun_boot_early_onertt / RFC 9001 5.7). No-op when nothing is held
 * or the slot was torn down inside the step. */
void srvrun_flush_held_on_confirm(
    const srvrun_step_ctx* ctx, int slot, int booting) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (booting && !srvrun_awaiting_confirm(c)) {
    srvrun_boot_flush_zerortt(ctx, c, slot);
  }
}

void srvrun_serve_slot(const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  srvrun_conn* c       = &ctx->st->conns[slot];
  int          booting = srvrun_awaiting_confirm(c);
  c->last_ms    = ctx->now_ms; /* RFC 9000 10.1: activity resets idle age */
  c->idle_tx_ms = 0;           /* the next ack-eliciting send restarts it */
  /* RFC 9000 8.1: every physically received byte counts toward this path's
   * antiamp budget, whether or not dg turns out to parse. */
  c->boot_rx_bytes += dg.n;
  /* RFC 9000 13.4.1 / 21.10: the codepoint is counted per processed
   * packet inside the step (srvloop step_note_ecn), never here before
   * decryption. Held early datagrams replayed in this call
   * (srvrun_flush_held_on_confirm) carry this datagram's codepoint.
   * shortcut: held datagrams do not keep their own mark; store it beside
   * zerortt_dg if a path ever remarks mid-handshake. */
  c->l.rx_ecn  = ctx->ecn;
  int consumed = srvrun_serve_boot(ctx, slot, dg);
  /* confirm may have landed inside serve_boot: seed the RTT estimators
   * from the boot flight's round trip either way (no-op off the edge). */
  srvrun_seed_boot_rtt(c, booting, ctx->now_ms);
  if (consumed) {
    return;
  }
  if (c->up) {
    srvrun_reconfirm_on_hs_probe(ctx, c, dg);
    srvrun_step_and_reap(ctx, slot, dg);
  }
  srvrun_resend_flight_on_hs_probe(ctx, c, booting, dg);
  srvrun_flush_held_on_confirm(ctx, slot, booting);
  srvrun_boot_release_pending(ctx, c);
}

/* dg's DCID as a span into dg, or a 0-length span if dg is too short to carry
 * the DCID length it claims (dcidresolve_dcid can't tell that apart from
 * a legitimate zero-length CID on its own, so reject dcid_len < 0 first). */
wired_span srvrun_dcid(wired_mspan dg, u8 short_hdr_len) {
  int dcid_len = dcidresolve_len(dg, short_hdr_len);
  if (dcid_len < 0) {
    return wired_span_of(0, 0);
  }
  return dcidresolve_dcid(dg, dcid_len);
}

/* Find the live slot this datagram's DCID matches. -1 if none does (the
 * datagram is malformed, or its DCID belongs to no connection this process
 * has open). */
int srvrun_find_slot(const srvrun_step_ctx* ctx, wired_span dcid) {
  if (dcid.p == 0) {
    return -1;
  }
  return conntable_find(
      ctx->st->table, WIRED_CONNTABLE_CAP, dcid.p, (u8)dcid.n);
}

/* Claim a free slot for a DCID no live connection matches. Only a fresh
 * Initial may open a new slot (RFC 9000 7) — a non-Initial datagram with an
 * unrecognized DCID (e.g. one arriving mid-migration, which this server does
 * not yet track, RFC 9000 9) is dropped instead of burning a slot per
 * datagram. Once graceful shutdown has been requested no new slot is claimed
 * either, so a brand-new client cannot start a connection during drain. -1 if
 * dcid is malformed, is_initial is false, shutdown is pending, or the table
 * is full. */
int srvrun_claim_refused(wired_span dcid, int is_initial) {
  return dcid.p == 0 || !is_initial || srvrun_shutdown_requested();
}

int srvrun_claim_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  if (srvrun_claim_refused(dcid, is_initial)) {
    return -1;
  }
  return conntable_insert(
      ctx->st->table, WIRED_CONNTABLE_CAP, dcid.p, (u8)dcid.n);
}

/* AF_XDP core-routing (see wired_srvrun_opt.core_id): only in XDP mode with a
 * non-negative core_id does a freshly generated CID get its leading byte
 * set to this worker's own core/queue index masked under the BPF program's
 * key (ncid_route_encode, RFC 9312 2.6: unreadable to on-path observers),
 * so the BPF filter can key an XSKMAP lookup off the CID instead of the
 * NIC's rx_queue_index.
 * Neither guard is a validating boundary -- ncid_route_encode itself
 * already no-ops (returns < 0) on a cid shorter than NCID_ROUTE_MIN_LEN;
 * there is simply nothing to embed into. */
static int srvrun_xdp_core_routing(const srvrun_cfg* cfg) {
  return cfg->xdp != 0 && cfg->core_id >= 0;
}

/* One place both a fresh accept (srvrun_open_slot) and any future additional-
 * CID issuance route through, so both share the exact same core-id embedding
 * policy (see NEW_CONNECTION_ID note in srvrun.h's core_id doc). Returns 1 on
 * success matching cid_generate's own contract. */
int srvrun_issue_cid(const srvrun_cfg* cfg, u8* cid, u8 cid_len) {
  if (!cid_generate(cid, cid_len)) {
    return 0;
  }
  if (srvrun_xdp_core_routing(cfg)) {
    ncid_route_encode(cid, cid_len, (u8)cfg->core_id, &cfg->xdp->route_key);
  }
  return 1;
}

int srvrun_cc_algo(const srvrun_cfg* cfg) {
  return cfg->cc_algo ? cfg->cc_algo : WIRED_CC_ALGO_DEFAULT;
}

/* RFC 9000 5.1.1: the one spare CID this slot's NEW_CONNECTION_ID frame
 * advertises at confirmation (respond.c's append_ncid_frame), with its
 * stateless reset token. Best-effort: an RNG failure just leaves
 * spare_cid_len 0 and no frame is ever sent -- the connection works, the
 * client simply cannot migrate. */
void srvrun_issue_spare_cid(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!srvrun_issue_cid(cfg, c->l.spare_cid, cfg->id->scid_len)) {
    return;
  }
  if (!cid_generate(c->l.spare_cid_token, NCID_TOKEN)) {
    return;
  }
  c->l.spare_cid_len = cfg->id->scid_len;
  c->mig.spare       = 1;
  c->mig.next        = 2;
}
