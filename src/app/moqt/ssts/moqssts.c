#include "app/moqt/ssts/moqssts.h"

#include "common/bytes/util/num.h"

/* Port of moqtail-ssts (ee9753c): lib.rs (budget, active_stream_depth),
 * algorithms/default/allocate.rs and algorithms/backpressure/state.rs +
 * mod.rs, registry.rs. Set masks are u32 bitmaps over at most
 * MOQSSTS_MAX_SETS sets. Weight sums and depth + timeouts are plain u64
 * adds: they wrap only far outside the documented ranges (weight 1..10,
 * stream counts), as moqtail's release-build arithmetic does. */

_Static_assert(MOQSSTS_MAX_SETS <= 32, "tier masks hold one bit per set");

int moqssts_alg_supported(u64 id) {
  return id == MOQSSTS_ALG_DEFAULT || id == MOQSSTS_ALG_BACKPRESSURE;
}

/* Every entry starts MOQSSTS_NONE, so sets past the cap stay answered. */
static void moqssts_none_all(int* out, usz n) {
  for (usz i = 0; i < n; i++) out[i] = MOQSSTS_NONE;
}

static usz moqssts_nsets(usz n) { return (usz)u64_min(n, MOQSSTS_MAX_SETS); }

static usz moqssts_nmem(const moqssts_set* s) {
  return (usz)u64_min(s->n_members, MOQSSTS_MAX_MEMBERS);
}

static int moqssts_has(u32 mask, usz i) { return (int)((mask >> i) & 1u); }

int moqssts_set_active(const moqssts_set* s) {
  return s->activate > 0 && moqssts_nmem(s) >= s->activate;
}

/* 0 means "no signal": it never constrains the budget. */
static u64 moqssts_or_max(u64 v) { return v ? v : ~0ULL; }

u64 moqssts_budget_kbps(u64 est_kbps, u64 cap_kbps) {
  return u64_min(moqssts_or_max(est_kbps), moqssts_or_max(cap_kbps));
}

u64 moqssts_active_depth(const moqssts_set* sets, usz n, const u64* open) {
  u64 sum = 0;
  n       = moqssts_nsets(n);
  for (usz i = 0; i < n; i++)
    sum += open[i] * (u64)moqssts_set_active(&sets[i]);
  return sum;
}

/* ===== default algorithm (allocate.rs) ===== */

static u64 moqssts_mul_sat(u64 a, u64 b) {
  if (b && a > ~0ULL / b) return ~0ULL;
  return a * b;
}

/* Highest member whose threshold <= target, or MOQSSTS_NONE. */
static int moqssts_member_up_to(const moqssts_set* s, u64 target) {
  for (usz i = moqssts_nmem(s); i > 0; i--)
    if (s->m[i - 1].threshold_kbps <= target) return (int)(i - 1);
  return MOQSSTS_NONE;
}

static u64 moqssts_sel_kbps(const moqssts_set* s, int sel) {
  if (sel < 0) return 0;
  return s->m[sel].threshold_kbps;
}

/* Selected its top track: it cannot use more of the pool. */
static int moqssts_is_saturated(const moqssts_set* s, int sel) {
  return sel >= 0 &&
         s->m[sel].threshold_kbps == s->m[moqssts_nmem(s) - 1].threshold_kbps;
}

static u32 moqssts_tier_mask(const moqssts_set* sets, usz n, u32 rank) {
  u32 mask = 0;
  for (usz i = 0; i < n; i++)
    mask |= (u32)(sets[i].rank == rank && moqssts_set_active(&sets[i])) << i;
  return mask;
}

static u64 moqssts_weight_sum(const moqssts_set* sets, usz n, u32 mask) {
  u64 total = 0;
  for (usz i = 0; i < n; i++) total += sets[i].weight * moqssts_has(mask, i);
  return u64_max(total, 1);
}

/* One round: every contending set picks against its weighted share; returns
 * the mask of sets that saturated. */
static u32 moqssts_round(
    const moqssts_set* sets, usz n, u32 contending, u64 pool, int* out) {
  u64 total = moqssts_weight_sum(sets, n, contending);
  u32 sat   = 0;
  for (usz i = 0; i < n; i++) {
    if (!moqssts_has(contending, i)) continue;
    out[i] = moqssts_member_up_to(
        &sets[i], moqssts_mul_sat(pool, sets[i].weight) / total);
    sat |= (u32)moqssts_is_saturated(&sets[i], out[i]) << i;
  }
  return sat;
}

/* Sum of the thresholds the sets in mask selected. */
static u64 moqssts_spent(
    const moqssts_set* sets, usz n, u32 mask, const int* out) {
  u64 spent = 0;
  for (usz i = 0; i < n; i++)
    spent += moqssts_sel_kbps(&sets[i], out[i]) * moqssts_has(mask, i);
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
  for (u32 rank = 0; rank < 256; rank++)
    moqssts_serve_tier(
        sets, n, moqssts_tier_mask(sets, n, rank), &remaining, out);
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

/* Uncongested: leave cooldown, count towards an upshift. high_streak is only
 * nonzero inside cooldown, so clearing it here equals clearing on exit. */
static int moqssts_bp_clear(moqssts_bp* st) {
  int exited      = st->in_cooldown;
  st->in_cooldown = 0;
  st->high_streak = 0;
  st->clear_streak++;
  if (st->clear_streak < MOQSSTS_UPSHIFT_GOP_STREAK)
    return exited ? MOQSSTS_EV_COOLDOWN_EXIT : MOQSSTS_EV_HELD;
  st->tier++;
  st->clear_streak = 0;
  return MOQSSTS_EV_UPSHIFT;
}

/* Congested outside cooldown: drop one tier and start settling down. */
static int moqssts_bp_congested(moqssts_bp* st, u64 depth) {
  st->clear_streak = 0;
  if (depth < MOQSSTS_DOWNSHIFT_DEPTH || st->tier == 0) return MOQSSTS_EV_HELD;
  st->tier--;
  st->in_cooldown  = 1;
  st->cooldown_ref = depth;
  st->high_streak  = 0;
  return MOQSSTS_EV_DOWNSHIFT;
}

static int moqssts_bp_drop(moqssts_bp* st) {
  st->tier--;
  st->high_streak = 0;
  return MOQSSTS_EV_DOWNSHIFT;
}

static int moqssts_bp_timeout_hit(const moqssts_bp* st, moqssts_obs ob) {
  return ob.timed_out && st->tier > 0;
}

static int moqssts_bp_rising_hit(const moqssts_bp* st) {
  return st->high_streak >= MOQSSTS_COOLDOWN_HIGH_STREAK && st->tier > 0;
}

/* Cooldown, no timeout: hold on steady/falling depth, drop after
 * COOLDOWN_HIGH_STREAK consecutive deeper groups. */
static int moqssts_bp_rising(moqssts_bp* st, u64 depth, u64 ref) {
  if (depth <= ref) {
    st->high_streak = 0;
    return MOQSSTS_EV_HELD;
  }
  st->high_streak++;
  if (!moqssts_bp_rising_hit(st)) return MOQSSTS_EV_HELD;
  return moqssts_bp_drop(st);
}

/* Congested during cooldown: a timeout on the tier just tried drops again. */
static int moqssts_bp_cooldown(moqssts_bp* st, moqssts_obs ob) {
  u64 ref          = st->cooldown_ref;
  st->clear_streak = 0;
  st->cooldown_ref = ob.depth;
  if (moqssts_bp_timeout_hit(st, ob)) return moqssts_bp_drop(st);
  return moqssts_bp_rising(st, ob.depth, ref);
}

int moqssts_bp_observe(moqssts_bp* st, moqssts_obs ob) {
  if (ob.depth <= MOQSSTS_DEPTH_TARGET) return moqssts_bp_clear(st);
  if (st->in_cooldown) return moqssts_bp_cooldown(st, ob);
  return moqssts_bp_congested(st, ob.depth);
}

/* Longest ladder - 1 (0 with no sets): the tier can go no higher. */
static u64 moqssts_bp_max_index(const moqssts_set* sets, usz n) {
  u64 longest = 0;
  for (usz i = 0; i < n; i++)
    longest = u64_max(longest, moqssts_nmem(&sets[i]));
  return u64_max(longest, 1) - 1;
}

/* Active sets (which have >= 1 member) forward the shared tier, clamped to
 * their own ladder. */
static int moqssts_bp_pick(u64 tier, const moqssts_set* s) {
  if (!moqssts_set_active(s)) return MOQSSTS_NONE;
  return (int)u64_min(tier, moqssts_nmem(s) - 1);
}

int moqssts_bp_decide(
    moqssts_bp*        st,
    const moqssts_set* sets,
    usz                n,
    const u64*         open,
    u64                timeouts,
    int*               out) {
  int ev;
  moqssts_none_all(out, n);
  n  = moqssts_nsets(n);
  ev = moqssts_bp_observe(
      st, moqssts_obs_make(moqssts_active_depth(sets, n, open), timeouts));
  st->tier = u64_min(st->tier, moqssts_bp_max_index(sets, n));
  for (usz i = 0; i < n; i++) out[i] = moqssts_bp_pick(st->tier, &sets[i]);
  return ev;
}
