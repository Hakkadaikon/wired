#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_slot_reset(const srvrun_step_ctx* ctx, usz i, wired_mspan dg);

/* --- RFC 9000 10.3.1: detecting the peer's Stateless Reset ---------------
 *
 * A datagram that no connection claims, or that its connection cannot
 * decrypt, is a Stateless Reset when its last 16 bytes are the token of a
 * peer connection ID this connection has sent with (peercid_reset_match).
 * The connection then enters the draining period and sends nothing more:
 * like a peer CONNECTION_CLOSE (srvrun_step_and_reap), its slot is freed,
 * its IDs kept as ghosts so the stragglers draw no reset of our own. */

/* 1 if dg is a Stateless Reset for c. */
int srvrun_peer_reset_hit(const srvrun_conn* c, wired_mspan dg) {
  return c->up && srvrun_short_header(dg) &&
         peercid_reset_match(&c->pcid, dg.p, dg.n);
}

void srvrun_peer_reset_drain(const srvrun_step_ctx* ctx, int slot) {
  srvrun_log_close(
      "conn closed by peer (stateless reset)", wired_span_of(0, 0));
  srvrun_note_ghost(ctx, &ctx->st->conns[slot]);
  srvrun_free_slot(ctx->cfg, ctx->st, slot);
}

/* Slot i is live and dg resets it. */
static int srvrun_slot_reset(
    const srvrun_step_ctx* ctx, usz i, wired_mspan dg) {
  return ctx->st->table[i].live &&
         srvrun_peer_reset_hit(&ctx->st->conns[i], dg);
}

/* A datagram no slot claimed: 1 if it reset (and drained) a connection. */
int srvrun_peer_reset_any(const srvrun_step_ctx* ctx, wired_mspan dg) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (srvrun_slot_reset(ctx, i, dg)) {
      srvrun_peer_reset_drain(ctx, (int)i);
      return 1;
    }
  }
  return 0;
}
