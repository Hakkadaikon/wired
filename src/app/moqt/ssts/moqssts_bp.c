#include "app/moqt/ssts/moqssts_impl.h"

static int moqssts_bp_clear(moqssts_bp* st);
static int moqssts_bp_congested(moqssts_bp* st, u64 depth);
static int moqssts_bp_drop(moqssts_bp* st);
static int moqssts_bp_timeout_hit(const moqssts_bp* st, moqssts_obs ob);
static int moqssts_bp_rising_hit(const moqssts_bp* st);
static int moqssts_bp_rising(moqssts_bp* st, u64 depth, u64 ref);
static int moqssts_bp_cooldown(moqssts_bp* st, moqssts_obs ob);
static u64 moqssts_bp_max_index(const moqssts_set* sets, usz n);
static int moqssts_bp_pick(u64 tier, const moqssts_set* s);

/* Uncongested: leave cooldown, count towards an upshift. high_streak is only
 * nonzero inside cooldown, so clearing it here equals clearing on exit. */
static int moqssts_bp_clear(moqssts_bp* st) {
  int exited      = st->in_cooldown;
  st->in_cooldown = 0;
  st->high_streak = 0;
  st->clear_streak++;
  if (st->clear_streak < MOQSSTS_UPSHIFT_GOP_STREAK) {
    return exited ? MOQSSTS_EV_COOLDOWN_EXIT : MOQSSTS_EV_HELD;
  }
  st->tier++;
  st->clear_streak = 0;
  return MOQSSTS_EV_UPSHIFT;
}

/* Congested outside cooldown: drop one tier and start settling down. */
static int moqssts_bp_congested(moqssts_bp* st, u64 depth) {
  st->clear_streak = 0;
  if (depth < MOQSSTS_DOWNSHIFT_DEPTH || st->tier == 0) {
    return MOQSSTS_EV_HELD;
  }
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
  if (!moqssts_bp_rising_hit(st)) {
    return MOQSSTS_EV_HELD;
  }
  return moqssts_bp_drop(st);
}

/* Congested during cooldown: a timeout on the tier just tried drops again. */
static int moqssts_bp_cooldown(moqssts_bp* st, moqssts_obs ob) {
  u64 ref          = st->cooldown_ref;
  st->clear_streak = 0;
  st->cooldown_ref = ob.depth;
  if (moqssts_bp_timeout_hit(st, ob)) {
    return moqssts_bp_drop(st);
  }
  return moqssts_bp_rising(st, ob.depth, ref);
}

int moqssts_bp_observe(moqssts_bp* st, moqssts_obs ob) {
  if (ob.depth <= MOQSSTS_DEPTH_TARGET) {
    return moqssts_bp_clear(st);
  }
  if (st->in_cooldown) {
    return moqssts_bp_cooldown(st, ob);
  }
  return moqssts_bp_congested(st, ob.depth);
}

/* Longest ladder - 1 (0 with no sets): the tier can go no higher. */
static u64 moqssts_bp_max_index(const moqssts_set* sets, usz n) {
  u64 longest = 0;
  for (usz i = 0; i < n; i++) {
    longest = u64_max(longest, moqssts_nmem(&sets[i]));
  }
  return u64_max(longest, 1) - 1;
}

/* Active sets (which have >= 1 member) forward the shared tier, clamped to
 * their own ladder. */
static int moqssts_bp_pick(u64 tier, const moqssts_set* s) {
  if (!moqssts_set_active(s)) {
    return MOQSSTS_NONE;
  }
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
  for (usz i = 0; i < n; i++) {
    out[i] = moqssts_bp_pick(st->tier, &sets[i]);
  }
  return ev;
}
