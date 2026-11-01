/* Bounded model check of the WebTransport session reference lifecycle
 * (issues #185/#186), run by `just cbmc`; not part of any build.
 *
 * Model: SLOTS session objects, each opened, closed and reopened in place
 * as srvrun does (open: stamp srvrun_wt_gen_next into the object's gen
 * and mark it active -- srvrun_start.c srvrun_wt_session_open,
 * srvrun_live.c srvrun_raw_start; release: clear active and zero gen --
 * srvrun_notify.c srvrun_close_wt_session_slot, srvrun_free.c
 * srvrun_close_all_wt; `grep -n "srvrun_wt_stamp\|->gen *= 0"` lists
 * them), and REFS references an application holds. A reference is taken
 * from an open or a released object, or names an object outside this env
 * (another worker's). Resolution is the SDK's own srvrun_wt_ref_resolves
 * (srvrun_gen.h); `owned` stands for srvrun_session_conn: the pointer is
 * one of this env's objects and open. mock_session stands for
 * wired_wt_session with only the field this property turns on (its
 * generation) -- srvrun_gen.h's doc explains why: CBMC bit-blasts the
 * real ~1.2 KiB struct's unused bytes, and swapping it in here (same
 * SLOTS, same STEPS, nothing else changed) turned an 11-second run into
 * one still running after 3 minutes. Ghost counters record which opening
 * each object holds and which each reference was taken from.
 *
 * Property, for every interleaving of STEPS operations and every starting
 * counter value (the 2^32 wrap included): a reference resolves iff it
 * names this env's object, that object is open, and it still holds the
 * opening the reference was taken from -- a reference to a released or
 * reused slot, or to another env's object, never resolves.
 *
 * Scope: this file covers the application-held WebTransport reference;
 * verify/cbmc/conn_gen.c covers the connection generation the datagram
 * ring and broadcast check use. Pointers the SDK clears synchronously
 * when a session closes (MoQT hub tables, WT stream and send slots) are
 * covered by unit tests (moqtrun_sub_test, srvrun_close_test), not here.
 * Bounded, not a full proof: a false match would need 2^32 openings of
 * one env between taking and using a reference. */

#include "app/http3/server/srvrun/srvrun_gen.h"

#define SLOTS 2
#define REFS 3
#define STEPS 7

int nondet_int(void);
u32 nondet_u32(void);

typedef struct {
  u32 gen;
} mock_session;

static mock_session s[SLOTS];
static mock_session foreign;              /* another worker's object */
static int          active[SLOTS];
static u32           opening[SLOTS];      /* ghost: which opening is live */
static const void*   ref_s[REFS];         /* wired_wt_ref.s, as void* */
static u32            ref_gen[REFS];      /* wired_wt_ref.gen */
static int            ref_slot[REFS];     /* ghost: -1 = not this env's */
static u32            ref_opening[REFS];  /* ghost: 0 = taken while closed */
static u32            last;               /* env->wt_gen_last */
static u32            openings;           /* ghost opening counter */

static int slot_of(const void* p) {
  for (int i = 0; i < SLOTS; i++) {
    if (p == &s[i]) {
      return i;
    }
  }
  return -1;
}

/* Stands for srvrun_wt_owned (srvrun_wt_ref.c). */
static int owned(const void* p, u32* cur_gen) {
  int i = slot_of(p);
  if (i < 0 || !active[i]) {
    return 0;
  }
  *cur_gen = s[i].gen;
  return 1;
}

static void op_open(int i) {
  __CPROVER_assume(!active[i]);
  s[i].gen   = srvrun_wt_gen_next(&last);
  active[i]  = 1;
  opening[i] = ++openings;
}

static void op_close(int i) {
  __CPROVER_assume(active[i]);
  active[i] = 0;
  s[i].gen  = 0;
}

static void op_take(int i, int j) {
  ref_s[j]       = &s[i];
  ref_gen[j]     = s[i].gen;
  ref_slot[j]    = i;
  ref_opening[j] = active[i] ? opening[i] : 0;
}

static void op_take_foreign(int j) {
  /* foreign.gen and the taken reference's own gen are each fixed once in
   * main, not freshly symbolic per call: the property does not depend on
   * their values (owned() rejects any pointer outside s[], whatever gen
   * it carries), and giving each call its own pair of free u32s is what
   * made this file time out. */
  ref_s[j]       = &foreign;
  ref_gen[j]     = foreign.gen + 1; /* deliberately may or may not match */
  ref_slot[j]    = -1;
  ref_opening[j] = 0;
}

static void op_use(int j) {
  int i    = ref_slot[j];
  int got  = srvrun_wt_ref_resolves(ref_s[j], ref_gen[j], owned);
  int live = ref_s[j] && i >= 0 && active[i] && ref_opening[j] &&
             opening[i] == ref_opening[j];
  __CPROVER_assert(got == live, "resolves iff its own opening is live");
}

int main(void) {
  last        = nondet_u32();
  foreign.gen = nondet_u32();
  for (int k = 0; k < STEPS; k++) {
    int op = nondet_int(), i = nondet_int(), j = nondet_int();
    __CPROVER_assume(op >= 0 && op <= 4 && i >= 0 && i < SLOTS && j >= 0 &&
                      j < REFS);
    if (op == 0) {
      op_open(i);
    } else if (op == 1) {
      op_close(i);
    } else if (op == 2) {
      op_take(i, j);
    } else if (op == 3) {
      op_take_foreign(j);
    } else {
      op_use(j);
    }
  }
  return 0;
}
