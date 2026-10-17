#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_table_full(const srvrun_state* st);
static int srvrun_evict_prefer(const srvrun_state* st, usz i, int best);
static int srvrun_evict_candidate(const srvrun_state* st);
static int srvrun_evict_grace_ok(const srvrun_step_ctx* ctx, int cand);
static int srvrun_evict_applies(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial);
static int srvrun_sreset_applies(wired_span dcid, wired_mspan dg);
static int srvrun_seal_stateless_reset(
    const srvrun_cfg* cfg, wired_span dcid, usz trigger_len, wired_obuf* out);

/* The slot dg routes to: an existing DCID match, a pending boot the client
 * switched its DCID onto, else a fresh claim (only for a new Initial); -1
 * when none. */
int srvrun_route(const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  int slot = srvrun_find_slot(ctx, dcid);
  if (slot >= 0) return slot;
  slot = srvrun_find_boot_scid(ctx, dcid);
  if (slot >= 0) return slot;
  return srvrun_open_slot(ctx, dcid, wired_srvboot_is_initial(dg.p, dg.n));
}

/* 1 if every conntable entry is live -- eviction is strictly the full-table
 * fallback; with a free entry the normal claim path must be the one that
 * admits (a claim that failed for any other reason must not cost a live
 * connection its slot). */
static int srvrun_table_full(const srvrun_state* st) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++)
    if (!st->table[i].live) return 0;
  return 1;
}

/* 1 if slot i beats the best-so-far eviction candidate: only a busy slot
 * competes at all (a freed slot's stale last_ms must never make it look
 * "oldest"), and among busy slots the smallest last_ms wins. */
static int srvrun_evict_prefer(const srvrun_state* st, usz i, int best) {
  if (!srvrun_slot_busy(&st->conns[i])) return 0;
  return best < 0 || st->conns[i].last_ms < st->conns[best].last_ms;
}

/* The oldest busy slot, -1 if none is busy. Whether it is idle enough to
 * actually evict is the caller's grace check -- the oldest busy slot being
 * under the grace floor means no slot at all is over it. */
static int srvrun_evict_candidate(const srvrun_state* st) {
  int best = -1;
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++)
    if (srvrun_evict_prefer(st, i, best)) best = (int)i;
  return best;
}

static int srvrun_evict_grace_ok(const srvrun_step_ctx* ctx, int cand) {
  return cand >= 0 && ctx->now_ms - ctx->st->conns[cand].last_ms >=
                          WIRED_SRVRUN_EVICT_GRACE_MS;
}

/* Eviction applies only when a datagram eligible to open a connection at
 * all (fresh Initial, sane DCID, no shutdown pending -- the same gate the
 * normal claim uses) found the table genuinely full. */
static int srvrun_evict_applies(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  return !srvrun_claim_refused(dcid, is_initial) && srvrun_table_full(ctx->st);
}

/* Full-table fallback for a new client's Initial: free the oldest slot idle
 * at least the grace floor and claim its place, all within this one
 * datagram's processing (no candidate is remembered across steps -- a slot
 * picked earlier could have been freed or sprung back to life by the time a
 * later step fired). Returns the freshly opened slot, or -1 (caller sends
 * the refusal) when no slot has been idle long enough. */
int srvrun_evict_for_initial(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  int cand;
  if (!srvrun_evict_applies(ctx, dcid, is_initial)) return -1;
  cand = srvrun_evict_candidate(ctx->st);
  if (!srvrun_evict_grace_ok(ctx, cand)) return -1;
  srvrun_log_close(
      "conn dropped: evicted for a new client", wired_span_of(0, 0));
  srvrun_free_slot(ctx->cfg, ctx->st, cand);
  return srvrun_open_slot(ctx, dcid, is_initial);
}

/* RFC 9000 10.3: a stateless reset answers a short-header datagram whose
 * DCID matches no live connection -- the client is talking to a server that
 * lost (or never had) its state, and without the reset it keeps
 * retransmitting into silence until its own idle timeout. Never for an
 * Initial (that path gets the CONNECTION_CLOSE refusal instead), and never
 * for a datagram too small to answer with something strictly smaller
 * (RFC 9000 10.3.3's loop-prevention rule: every reset sent must be smaller
 * than the packet that triggered it). */
static int srvrun_sreset_applies(wired_span dcid, wired_mspan dg) {
  return dcid.p != 0 && !wired_srvboot_is_initial(dg.p, dg.n) &&
         dg.n > SRESET_MIN;
}

/* Build the reset for dcid: random-looking bytes ending in the token the
 * connection's handshake advertised (same sreset_key_derive derivation
 * srvboot used, so the token survives a server restart -- the exact
 * situation this packet exists for). Capacity is clamped below the
 * triggering datagram's size (10.3.3). */
static int srvrun_seal_stateless_reset(
    const srvrun_cfg* cfg, wired_span dcid, usz trigger_len, wired_obuf* out) {
  u8         key[SRESET_KEY];
  wired_obuf ob = obuf_of(out->p, u64_min(out->cap, trigger_len - 1));
  sreset_key_derive(srvboot_reset_seed(cfg->id), key);
  if (!sreset_build(key, dcid.p, dcid.n, trigger_len, rng_bytes, &ob)) return 0;
  out->len = ob.len;
  return 1;
}

void srvrun_send_stateless_reset(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_sreset_applies(dcid, dg)) return;
  if (!srvrun_seal_stateless_reset(ctx->cfg, dcid, dg.n, &ob)) return;
  srvrun_tx(
      ctx->cfg, srvrun_rx_fd(ctx->cfg), ctx->peer, wired_span_of(out, ob.len));
}
