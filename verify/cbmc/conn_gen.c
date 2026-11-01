/* Bounded model check of the connection-slot generation (issue #186), run
 * by `just cbmc`; not part of any build.
 *
 * Model: SLOTS connection slots claimed, brought up, freed and claimed
 * again in place as srvrun does (claim: gen = srvrun_conn_gen_next, up = 0
 * -- srvrun_retry.c srvrun_conn_fresh; up after the handshake --
 * srvrun_http.c; free: up = 0 -- srvrun_free.c srvrun_free_slot), and
 * ENTRIES datagram-ring entries queued for an up connection with its slot
 * and generation (srvrun_dgring.c). Draining an entry asks the SDK's own
 * srvrun_conn_gen_live (srvrun_gen.h), as srvrun_dgring_live does. Ghost
 * counters record which claim each slot holds and each entry targets.
 *
 * Property, for every interleaving of STEPS operations and every starting
 * generation (the 2^32 wrap included): an entry is sent iff its slot is up
 * and still holds the claim it was queued for -- never to a freed slot or
 * to the next client that claimed it. Bounded, not a full proof: a false
 * match would need 2^32 claims of one slot while an entry waits. */

#include "app/http3/server/srvrun/srvrun_gen.h"

#define SLOTS 2
#define ENTRIES 3
#define STEPS 8

int  nondet_int(void);
u32  nondet_u32(void);

static u32 gen[SLOTS];
static int up[SLOTS], claimed[SLOTS];
static u32 claim[SLOTS]; /* ghost: which claim the slot holds */
static int e_used[ENTRIES], e_slot[ENTRIES];
static u32 e_gen[ENTRIES], e_claim[ENTRIES];
static u32 claims;

static void op_claim(int i) {
  __CPROVER_assume(!claimed[i]);
  gen[i]     = srvrun_conn_gen_next(gen[i]);
  claimed[i] = 1;
  up[i]      = 0;
  claim[i]   = ++claims;
}

static void op_up(int i) {
  __CPROVER_assume(claimed[i] && !up[i]);
  up[i] = 1;
}

static void op_free(int i) {
  __CPROVER_assume(claimed[i]);
  claimed[i] = 0;
  up[i]      = 0;
}

static void op_queue(int i, int j) {
  __CPROVER_assume(up[i]);
  e_used[j]  = 1;
  e_slot[j]  = i;
  e_gen[j]   = gen[i];
  e_claim[j] = claim[i];
}

static void op_drain(int j) {
  int i = e_slot[j];
  __CPROVER_assume(e_used[j]);
  int sent = srvrun_conn_gen_live(up[i], gen[i], e_gen[j]);
  int live = up[i] && claim[i] == e_claim[j];
  __CPROVER_assert(sent == live, "sent iff its own claim is up");
  e_used[j] = 0;
}

int main(void) {
  for (int i = 0; i < SLOTS; i++) {
    gen[i] = nondet_u32();
  }
  for (int k = 0; k < STEPS; k++) {
    int op = nondet_int(), i = nondet_int(), j = nondet_int();
    __CPROVER_assume(i >= 0 && i < SLOTS && j >= 0 && j < ENTRIES);
    if (op == 0) {
      op_claim(i);
    } else if (op == 1) {
      op_up(i);
    } else if (op == 2) {
      op_free(i);
    } else if (op == 3) {
      op_queue(i, j);
    } else {
      op_drain(j);
    }
  }
  return 0;
}
