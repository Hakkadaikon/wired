#include "app/http3/server/srvrun/srvrun_gen.h"
#include "app/http3/server/srvrun/srvrun_impl.h"

static u64  srvrun_dgring_wait_ms(const srvrun_conn* c);
static void srvrun_dgring_stamp(srvrun_dgring_entry* e, u64 now_ms);
static int  srvrun_dgring_late(
    srvrun_state* st, const srvrun_dgring_entry* e, u64 now_ms);
static int srvrun_dgring_for(
    srvrun_state* st, const srvrun_dgring_entry* e, int slot);

/* How long a ring datagram may wait behind its own connection's streams
 * (RFC 9221 5.1 leaves the order to the app; liveness bounds it): two
 * smoothed RTTs, so stream priority keeps a round trip or two of
 * precedence, floored at SRVRUN_PTO_MS, the poll tick -- the longest gap
 * between two send passes, so a shorter bound could not be honored. */
static u64 srvrun_dgring_wait_ms(const srvrun_conn* c) {
  return u64_max(2 * c->srtt_ms, SRVRUN_PTO_MS);
}

/* Stamp e the first time a send pass finds it at its connection's front. */
static void srvrun_dgring_stamp(srvrun_dgring_entry* e, u64 now_ms) {
  if (!e->seen_ms) {
    e->seen_ms = now_ms;
  }
}

/* 1 when e has waited past its connection's srvrun_dgring_wait_ms. */
static int srvrun_dgring_late(
    srvrun_state* st, const srvrun_dgring_entry* e, u64 now_ms) {
  return now_ms >= e->seen_ms + srvrun_dgring_wait_ms(&st->conns[e->conn_slot]);
}

/* 1 iff e is queued for the connection now on slot -- an entry of a client
 * that left the slot (dropped at the next drain) holds nobody back. */
static int srvrun_dgring_for(
    srvrun_state* st, const srvrun_dgring_entry* e, int slot) {
  return e->conn_slot == slot &&
         srvrun_conn_gen_live(
             st->conns[slot].up, st->conns[slot].gen, e->conn_gen);
}

/* Only slot's oldest live entry is stamped and checked: each datagram's wait
 * starts when it reaches the front of its connection's queue, so the
 * streams get a full wait between two overdue datagrams even when the ring
 * stays full (no stream starvation under a datagram flood). */
int srvrun_dgring_overdue(const srvrun_step_ctx* ctx, int slot) {
  wired_srvrun_env* env = ctx->cfg->env;
  for (usz i = 0; i < env->dgring_n; i++) {
    srvrun_dgring_entry* e =
        &env->dgring[(env->dgring_head + i) % SRVRUN_DGRING_CAP];
    if (srvrun_dgring_for(ctx->st, e, slot)) {
      srvrun_dgring_stamp(e, ctx->now_ms);
      return srvrun_dgring_late(ctx->st, e, ctx->now_ms);
    }
  }
  return 0;
}
