#include "app/moqt/ssts/moqssts_impl.h"

static u64 moqssts_spent(
    const moqssts_set* sets, usz n, u32 mask, const int* out);
static u64  moqssts_sub_sat(u64 a, u64 b);
static void moqssts_serve_tier(
    const moqssts_set* sets, usz n, u32 tier, u64* remaining, int* out);

/* Sum of the thresholds the sets in mask selected. */
static u64 moqssts_spent(
    const moqssts_set* sets, usz n, u32 mask, const int* out) {
  u64 spent = 0;
  for (usz i = 0; i < n; i++) {
    spent += moqssts_sel_kbps(&sets[i], out[i]) * moqssts_has(mask, i);
  }
  return spent;
}

static u64 moqssts_sub_sat(u64 a, u64 b) { return a - u64_min(a, b); }

/* Serve one rank tier from *remaining: saturated sets leave the pool and
 * hand their unused share to the rest, until no set saturates. */
static void moqssts_serve_tier(
    const moqssts_set* sets, usz n, u32 tier, u64* remaining, int* out) {
  u32 contending = tier;
  u64 pool       = *remaining;
  u32 sat        = moqssts_round(sets, n, contending, pool, out);
  while (sat) {
    pool = moqssts_sub_sat(pool, moqssts_spent(sets, n, sat, out));
    contending &= ~sat;
    sat = moqssts_round(sets, n, contending, pool, out);
  }
  *remaining = moqssts_sub_sat(*remaining, moqssts_spent(sets, n, tier, out));
}

void moqssts_default_decide(
    u64 budget_kbps, const moqssts_set* sets, usz n, int* out) {
  u64 remaining = u64_min(budget_kbps, MOQSSTS_UNLIMITED_KBPS);
  moqssts_none_all(out, n);
  n = moqssts_nsets(n);
  /* Strict priority: rank 0 first, each tier before the next sees anything. */
  for (u32 rank = 0; rank < 256; rank++) {
    moqssts_serve_tier(
        sets, n, moqssts_tier_mask(sets, n, rank), &remaining, out);
  }
}

/* ===== backpressure algorithm (backpressure/state.rs, mod.rs) ===== */

void moqssts_bp_init(moqssts_bp* st) {
  st->tier         = 0;
  st->clear_streak = 0;
  st->in_cooldown  = 0;
  st->cooldown_ref = 0;
  st->high_streak  = 0;
}

moqssts_obs moqssts_obs_make(u64 depth, u64 timeouts) {
  moqssts_obs ob;
  ob.depth     = depth + timeouts;
  ob.timed_out = timeouts > 0;
  return ob;
}
