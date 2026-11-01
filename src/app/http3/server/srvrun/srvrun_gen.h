#ifndef WIRED_SRVRUN_GEN_H
#define WIRED_SRVRUN_GEN_H

#include "common/platform/sys/syscall.h"

/* Issues #185/#186: the generation decisions that tell a reused slot from
 * the one a reference was taken for, kept free of the env (and of the
 * real wired_wt_session/wired_wt_ref types -- see srvrun_wt_ref_resolves'
 * doc) so the bounded model checks in verify/cbmc run this very code
 * against a small mock object instead of the real ~1.2 KiB session
 * struct, which CBMC bit-blasts field by field and chokes on. */

/* The session generation after *last, never 0 (0 marks a released
 * session, so no open session matches a zeroed reference). */
static inline u32 srvrun_wt_gen_next(u32* last) {
  *last += 1 + (*last == (u32)-1);
  return *last;
}

/* r_s is named and r_gen is not the always-invalid 0 -- the shape a
 * reference must have before it is worth asking owned() about. The
 * `r_gen` half is defense in depth, not load-bearing: every open site
 * stamps a non-zero generation before marking the object active
 * (srvrun_start.c, srvrun_live.c), so owned() never reports an active
 * object with gen 0, and verify/cbmc/wt_ref.c's mutation check (a mutant
 * that drops this half) cannot distinguish it from the unmutated code
 * for exactly that reason -- confirmed by reading both open sites, not
 * just by the model's silence on the mutant. */
static inline int srvrun_wt_ref_shaped(const void* r_s, u32 r_gen) {
  return r_s != 0 && r_gen != 0;
}

/* wired_wt_ref_get's rule: a reference names an open object of the
 * caller's own, holding the generation the reference was taken for. r_s
 * is the reference's void* session pointer and r_gen its generation
 * (wired_wt_ref's two fields, read by the caller so this stays
 * independent of that type); owned(r_s) is asked first (so another
 * worker's object is never read) and, when it does own r_s, writes that
 * object's current generation to *cur_gen. */
static inline int srvrun_wt_ref_resolves(
    const void* r_s, u32 r_gen, int (*owned)(const void* s, u32* cur_gen)) {
  u32 cur_gen = 0;
  if (!srvrun_wt_ref_shaped(r_s, r_gen) || !owned(r_s, &cur_gen)) {
    return 0;
  }
  return cur_gen == r_gen;
}

/* The connection generation a claim gives a slot that held gen. */
static inline u32 srvrun_conn_gen_next(u32 gen) { return gen + 1; }

/* A reference queued for the connection of generation want (a datagram
 * ring entry) still reaches it: the slot is up and holds that claim. */
static inline int srvrun_conn_gen_live(int up, u32 gen, u32 want) {
  return up && gen == want;
}

#endif
