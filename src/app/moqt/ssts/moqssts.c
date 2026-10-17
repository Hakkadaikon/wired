#include "app/moqt/ssts/moqssts_impl.h"

static u64 moqssts_or_max(u64 v);
static u64 moqssts_mul_sat(u64 a, u64 b);
static int moqssts_member_up_to(const moqssts_set* s, u64 target);
static int moqssts_is_saturated(const moqssts_set* s, int sel);
static u64 moqssts_weight_sum(const moqssts_set* sets, usz n, u32 mask);

int moqssts_alg_supported(u64 id) {
  return id == MOQSSTS_ALG_DEFAULT || id == MOQSSTS_ALG_BACKPRESSURE;
}

/* Every entry starts MOQSSTS_NONE, so sets past the cap stay answered. */
void moqssts_none_all(int* out, usz n) {
  for (usz i = 0; i < n; i++) {
    out[i] = MOQSSTS_NONE;
  }
}

usz moqssts_nsets(usz n) { return (usz)u64_min(n, MOQSSTS_MAX_SETS); }

usz moqssts_nmem(const moqssts_set* s) {
  return (usz)u64_min(s->n_members, MOQSSTS_MAX_MEMBERS);
}

int moqssts_has(u32 mask, usz i) { return (int)((mask >> i) & 1u); }

int moqssts_set_active(const moqssts_set* s) {
  return s->activate > 0 && moqssts_nmem(s) >= s->activate;
}

/* 0 means "no signal": it never constrains the budget. */
static u64 moqssts_or_max(u64 v) { return v ? v : ~0ULL; }

u64 moqssts_budget_kbps(u64 est_kbps, u64 cap_kbps) {
  return u64_min(moqssts_or_max(est_kbps), moqssts_or_max(cap_kbps));
}

/* moqtail sums the sets (lib.rs active_stream_depth), which pins two
 * sharers with one stream each at DOWNSHIFT_DEPTH; the deepest set keeps
 * the per-track meaning of the thresholds. */
u64 moqssts_active_depth(const moqssts_set* sets, usz n, const u64* open) {
  u64 deepest = 0;
  n           = moqssts_nsets(n);
  for (usz i = 0; i < n; i++) {
    deepest = u64_max(deepest, open[i] * (u64)moqssts_set_active(&sets[i]));
  }
  return deepest;
}

/* ===== default algorithm (allocate.rs) ===== */

static u64 moqssts_mul_sat(u64 a, u64 b) {
  if (b && a > ~0ULL / b) {
    return ~0ULL;
  }
  return a * b;
}

/* Highest member whose threshold <= target, or MOQSSTS_NONE. */
static int moqssts_member_up_to(const moqssts_set* s, u64 target) {
  for (usz i = moqssts_nmem(s); i > 0; i--) {
    if (s->m[i - 1].threshold_kbps <= target) {
      return (int)(i - 1);
    }
  }
  return MOQSSTS_NONE;
}

u64 moqssts_sel_kbps(const moqssts_set* s, int sel) {
  if (sel < 0) {
    return 0;
  }
  return s->m[sel].threshold_kbps;
}

/* Selected its top track: it cannot use more of the pool. */
static int moqssts_is_saturated(const moqssts_set* s, int sel) {
  return sel >= 0 &&
         s->m[sel].threshold_kbps == s->m[moqssts_nmem(s) - 1].threshold_kbps;
}

u32 moqssts_tier_mask(const moqssts_set* sets, usz n, u32 rank) {
  u32 mask = 0;
  for (usz i = 0; i < n; i++) {
    mask |= (u32)(sets[i].rank == rank && moqssts_set_active(&sets[i])) << i;
  }
  return mask;
}

static u64 moqssts_weight_sum(const moqssts_set* sets, usz n, u32 mask) {
  u64 total = 0;
  for (usz i = 0; i < n; i++) {
    total += sets[i].weight * moqssts_has(mask, i);
  }
  return u64_max(total, 1);
}

/* One round: every contending set picks against its weighted share; returns
 * the mask of sets that saturated. */
u32 moqssts_round(
    const moqssts_set* sets, usz n, u32 contending, u64 pool, int* out) {
  u64 total = moqssts_weight_sum(sets, n, contending);
  u32 sat   = 0;
  for (usz i = 0; i < n; i++) {
    if (!moqssts_has(contending, i)) {
      continue;
    }
    out[i] = moqssts_member_up_to(
        &sets[i], moqssts_mul_sat(pool, sets[i].weight) / total);
    sat |= (u32)moqssts_is_saturated(&sets[i], out[i]) << i;
  }
  return sat;
}
