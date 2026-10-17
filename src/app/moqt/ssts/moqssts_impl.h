#ifndef APP_MOQT_SSTS_MOQSSTS_IMPL_H
#define APP_MOQT_SSTS_MOQSSTS_IMPL_H

/* Internal to the moqssts*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/ssts/moqssts.h"
#include "common/bytes/util/num.h"

/* Port of moqtail-ssts (ee9753c): lib.rs (budget, active_stream_depth),
 * algorithms/default/allocate.rs and algorithms/backpressure/state.rs +
 * mod.rs, registry.rs. Set masks are u32 bitmaps over at most
 * MOQSSTS_MAX_SETS sets. Weight sums and depth + timeouts are plain u64
 * adds: they wrap only far outside the documented ranges (weight 1..10,
 * stream counts), as moqtail's release-build arithmetic does. */

_Static_assert(MOQSSTS_MAX_SETS <= 32, "tier masks hold one bit per set");

void moqssts_none_all(int* out, usz n);
usz  moqssts_nsets(usz n);
usz  moqssts_nmem(const moqssts_set* s);
int  moqssts_has(u32 mask, usz i);
u64  moqssts_sel_kbps(const moqssts_set* s, int sel);
u32  moqssts_tier_mask(const moqssts_set* sets, usz n, u32 rank);
u32  moqssts_round(
    const moqssts_set* sets, usz n, u32 contending, u64 pool, int* out);

#endif
