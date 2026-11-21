#include "app/http3/server/srvrun/srvrun_impl.h"
#include "app/http3/server/srvsteer/srvsteer.h"

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
  c->last_ms = ctx->now_ms;  /* RFC 9000 10.1: activity resets idle age */
  c->l.ackst.idle_tx_ms = 0; /* the next ack-eliciting send restarts it */
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

/* AF_XDP core-routing (see wired_srvrun_opt.core_id): in XDP mode a worker
 * that receives a short header on its queue decodes the DCID's leading byte
 * under the key and hands the datagram to that worker (srvxdp_fwd.c, RFC
 * 9000 9), so every CID this server issues carries its owner -- the
 * worker's core_id, or, with core_id -1 (a single AF_XDP socket), that
 * socket's own queue. ncid_route_encode itself no-ops on a cid shorter
 * than NCID_ROUTE_MIN_LEN; there is simply nothing to embed into. */
static int srvrun_xdp_core_routing(const srvrun_cfg* cfg) {
  return cfg->xdp != 0;
}

/* The owning worker index this server's CIDs carry (see above). */
static u8 srvrun_xdp_core(const srvrun_cfg* cfg) {
  return (u8)(cfg->core_id >= 0 ? (u32)cfg->core_id : cfg->xdp->queue_id);
}

/* RFC 9000 5.2 / 9: in a steered multi-worker UDP run the reuseport BPF
 * program decodes every DCID's leading byte under the shared key, so every
 * CID this worker issues must carry its own index -- exactly the AF_XDP
 * rule above, same key scheme, different transport. The run is steered
 * exactly when the socket it serves IS its worker's steering socket
 * (srvsteer_owns): a run on any other socket -- the preferred-address
 * port, or a serve_env outside the group -- must not embed bytes under a
 * key its packets never traverse. */
int srvrun_udp_steer_routing(const srvrun_cfg* cfg) {
  return !cfg->xdp && cfg->core_id >= 0 && srvsteer_owns(cfg->fd, cfg->core_id);
}

/* Embed the issuing worker's routing byte into cid, under whichever of the
 * two steering paths (AF_XDP forwarding / reuseport BPF) this run uses;
 * a plain single-socket run leaves the CID fully random. */
static void srvrun_route_cid(const srvrun_cfg* cfg, u8* cid, u8 cid_len) {
  if (srvrun_xdp_core_routing(cfg)) {
    ncid_route_encode(cid, cid_len, srvrun_xdp_core(cfg), &cfg->xdp->route_key);
    return;
  }
  if (srvrun_udp_steer_routing(cfg)) {
    ncid_route_encode(cid, cid_len, (u8)cfg->core_id, srvsteer_key());
  }
}

/* Test seam (srvworkers_test_set_child_fn precedent): substitute the raw
 * CID draw so the collision redraw below is testable against a scripted
 * sequence. Pass 0 to restore the real CSPRNG draw. */
typedef int (*srvrun_cid_draw_fn)(u8* cid, u8 len);
static srvrun_cid_draw_fn g_srvrun_cid_draw = cid_generate;

__attribute__((unused)) static void srvrun_test_set_cid_draw(
    srvrun_cid_draw_fn fn) {
  g_srvrun_cid_draw = fn ? fn : cid_generate;
}

/* Draw + route one candidate and accept it only if no live connection in t
 * already answers to it (RFC 9000 5.1 / 10.3.2: a connection ID must not
 * be reused for another connection under the same static reset key -- the
 * routed, final bytes are what the table and the reset key see, so the
 * check runs after the routing byte is embedded). */
static int srvrun_cid_fresh(
    const srvrun_cfg* cfg, const conntable* t, u8* cid, u8 cid_len) {
  if (!g_srvrun_cid_draw(cid, cid_len)) {
    return 0;
  }
  srvrun_route_cid(cfg, cid, cid_len);
  return conntable_find(t, WIRED_CONNTABLE_CAP, cid, cid_len) < 0;
}

/* Collision-redraw attempts: with <= 64 live connections' CIDs in a
 * >= 5-byte (routing byte + 4 mixed bytes) ID space, one redraw is already
 * vanishingly rare; 8 bounds the loop without ever mattering in practice. */
#define SRVRUN_CID_REDRAWS 8

/* One place both a fresh accept (srvrun_open_slot) and any additional-CID
 * issuance route through, so both share the exact same core-id embedding
 * policy (see NEW_CONNECTION_ID note in srvrun.h's core_id doc) and the
 * same across-connections uniqueness check. Returns 1 on success; 0 when
 * the RNG failed or every attempt collided (no CID issued -- callers treat
 * it exactly like an RNG failure). */
int srvrun_issue_cid(
    const srvrun_cfg* cfg, const conntable* t, u8* cid, u8 cid_len) {
  for (int i = 0; i < SRVRUN_CID_REDRAWS; i++) {
    if (srvrun_cid_fresh(cfg, t, cid, cid_len)) {
      return 1;
    }
  }
  return 0;
}

int srvrun_cc_algo(const srvrun_cfg* cfg) {
  return cfg->cc_algo ? cfg->cc_algo : WIRED_CC_ALGO_DEFAULT;
}

/* RFC 9000 5.1.1: the one spare CID this slot's NEW_CONNECTION_ID frame
 * advertises at confirmation (respond.c's append_ncid_frame), with its
 * stateless reset token derived from the worker's static reset key
 * (RFC 9000 10.3.2: reproducible when the reset is later built).
 * Best-effort: an RNG failure on the CID draw just leaves spare_cid_len 0
 * and no frame is ever sent -- the connection works, the client simply
 * cannot migrate. */
void srvrun_issue_spare_cid(
    const srvrun_cfg* cfg, const conntable* t, srvrun_conn* c) {
  if (!srvrun_issue_cid(cfg, t, c->l.spare_cid, cfg->id->scid_len)) {
    return;
  }
  srvboot_reset_token(
      cfg->id, c->l.spare_cid, cfg->id->scid_len, c->l.spare_cid_token);
  c->l.spare_cid_len = cfg->id->scid_len;
  c->mig.spare       = 1;
  c->mig.next        = 2;
}
