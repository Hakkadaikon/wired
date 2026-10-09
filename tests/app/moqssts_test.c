#include "app/moqt/ssts/moqssts.h"

#include "test.h"

/* @file
 * SSTS decision algorithms. Every expected value is moqtail's (third-party
 * oracle, moqtail ee9753c libs/moqtail-ssts): the default allocator cases from
 * src/algorithms/default/tests.rs, the backpressure cases from
 * src/algorithms/backpressure/tests.rs and the registry cases from
 * src/registry.rs -- one C test per Rust #[test] (renamed), plus
 * active_depth_counts_active_sets_only. The review-round tests after the
 * port (marked "derived") pin behaviour of the same Rust code computed by
 * hand from allocate.rs / state.rs, to kill surviving mutants. moqtail
 * answers with relay track ids; these tests map the chosen member index back
 * to its track id so the Rust assertions carry over verbatim. moqtail's
 * SetSnapshot.active bool is activate = 1 / 0 here. */

#define MOQSSTS_T_NONE (~0ULL)

typedef struct {
  u64 threshold;
  u64 track;
} moqssts_t_pair;

static moqssts_set moqssts_t_set(
    u64 id, u8 rank, u64 weight, int active, const moqssts_t_pair* p, usz n) {
  moqssts_set s  = {0};
  s.set_id       = id;
  s.algorithm_id = MOQSSTS_ALG_DEFAULT;
  s.rank         = rank;
  s.weight       = weight;
  s.activate     = active ? 1 : 0;
  s.n_members    = n;
  for (usz i = 0; i < n; i++) {
    s.m[i].threshold_kbps = p[i].threshold;
    s.m[i].track_id       = p[i].track;
  }
  return s;
}

static u64 moqssts_t_track(const moqssts_set* s, int idx) {
  if (idx < 0) return MOQSSTS_T_NONE;
  return s->m[idx].track_id;
}

/* allocate(budget, sets)[&sets[which].id] as a track id. */
static u64 moqssts_t_alloc(
    u64 budget, const moqssts_set* sets, usz n, usz which) {
  int out[MOQSSTS_MAX_SETS] = {0};
  moqssts_default_decide(budget, sets, n, out);
  return moqssts_t_track(&sets[which], out[which]);
}

/* ===== default/tests.rs ===== */

static void test_moqssts_budget_is_the_stricter_of_estimate_and_cap(void) {
  CHECK(moqssts_budget_kbps(1000, 500) == 500);
  CHECK(moqssts_budget_kbps(300, 500) == 300);
  CHECK(moqssts_budget_kbps(0, 500) == 500);
  CHECK(moqssts_budget_kbps(800, 0) == 800);
  CHECK(moqssts_budget_kbps(0, 0) == ~0ULL);
}

static void test_moqssts_single_set_picks_the_highest_affordable_track(void) {
  static const moqssts_t_pair l[] = {{500, 0}, {1000, 1}, {2000, 2}};
  moqssts_set                 s[] = {moqssts_t_set(1, 0, 5, 1, l, 3)};
  CHECK(moqssts_t_alloc(1500, s, 1, 0) == 1);
}

static void test_moqssts_two_sets_of_the_same_rank_split_by_weight(void) {
  static const moqssts_t_pair a[] = {{800, 10}, {1600, 11}};
  static const moqssts_t_pair b[] = {{500, 20}, {1000, 21}, {2000, 22}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 0, 6, 1, a, 2), moqssts_t_set(2, 0, 4, 1, b, 3)};
  CHECK(moqssts_t_alloc(3000, s, 2, 0) == 11);
  CHECK(moqssts_t_alloc(3000, s, 2, 1) == 21);
}

static void test_moqssts_a_saturated_set_gives_its_share_back(void) {
  static const moqssts_t_pair a[] = {{500, 10}};
  static const moqssts_t_pair b[] = {{1000, 20}, {2000, 21}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 0, 1, 1, a, 1), moqssts_t_set(2, 0, 1, 1, b, 2)};
  CHECK(moqssts_t_alloc(3000, s, 2, 0) == 10);
  CHECK(moqssts_t_alloc(3000, s, 2, 1) == 21);
}

static void test_moqssts_a_high_rank_is_served_before_a_low_one(void) {
  static const moqssts_t_pair a[] = {{2000, 10}};
  static const moqssts_t_pair b[] = {{500, 20}, {1000, 21}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 0, 1, 1, a, 1), moqssts_t_set(2, 1, 10, 1, b, 2)};
  CHECK(moqssts_t_alloc(3000, s, 2, 0) == 10);
  CHECK(moqssts_t_alloc(3000, s, 2, 1) == 21);
}

static void test_moqssts_default_an_inactive_set_forwards_nothing(void) {
  static const moqssts_t_pair a[] = {{500, 0}, {1000, 1}};
  static const moqssts_t_pair b[] = {{500, 2}, {1000, 3}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 0, 5, 0, a, 2), moqssts_t_set(2, 0, 5, 1, b, 2)};
  CHECK(moqssts_t_alloc(10000, s, 2, 0) == MOQSSTS_T_NONE);
  CHECK(moqssts_t_alloc(10000, s, 2, 1) == 3);
}

static void test_moqssts_a_budget_below_the_lowest_tier_forwards_nothing(void) {
  static const moqssts_t_pair l[] = {{500, 0}, {1000, 1}};
  moqssts_set                 s[] = {moqssts_t_set(1, 0, 5, 1, l, 2)};
  CHECK(moqssts_t_alloc(400, s, 1, 0) == MOQSSTS_T_NONE);
}

static void test_moqssts_a_zero_weight_set_is_never_served(void) {
  static const moqssts_t_pair a[] = {{500, 10}, {4000, 11}};
  static const moqssts_t_pair b[] = {{500, 20}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 0, 0, 1, a, 2), moqssts_t_set(2, 1, 1, 1, b, 1)};
  CHECK(moqssts_t_alloc(3000, s, 2, 0) == MOQSSTS_T_NONE);
  CHECK(moqssts_t_alloc(3000, s, 2, 1) == 20);
}

static void test_moqssts_every_set_gets_an_answer(void) {
  static const moqssts_t_pair a[] = {{500, 10}};
  static const moqssts_t_pair b[] = {{500, 20}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 3, 1, 0, a, 1), moqssts_t_set(2, 1, 1, 1, b, 1),
      moqssts_t_set(3, 1, 1, 1, 0, 0)};
  int out[3] = {99, 99, 99};
  moqssts_default_decide(10000, s, 3, out);
  CHECK(out[0] == MOQSSTS_NONE);
  CHECK(out[1] == 0);
  CHECK(out[2] == MOQSSTS_NONE);
}

static void test_moqssts_an_empty_set_list_decides_nothing(void) {
  int out[1] = {99};
  moqssts_default_decide(10000, 0, 0, out);
  CHECK(out[0] == 99);
}

/* ===== backpressure/tests.rs ===== */

/* A set with a three-rung ladder: 500, 1000 and 2000 kbps. */
static moqssts_set moqssts_t_bpset(u64 id, int active) {
  const moqssts_t_pair l[] = {
      {500, id * 10}, {1000, id * 10 + 1}, {2000, id * 10 + 2}};
  moqssts_set s  = moqssts_t_set(id, 0, 1, active, l, 3);
  s.algorithm_id = MOQSSTS_ALG_BACKPRESSURE;
  return s;
}

/* decide_once: one group, the first set's forwarded track id. */
static u64 moqssts_t_bp_once(
    moqssts_bp*        st,
    const moqssts_set* sets,
    usz                n,
    const u64*         open,
    u64                timeouts) {
  int out[MOQSSTS_MAX_SETS] = {0};
  moqssts_bp_decide(st, sets, n, open, timeouts, out);
  return moqssts_t_track(&sets[0], out[0]);
}

static void moqssts_t_climb(moqssts_bp* st, const moqssts_set* sets, int g) {
  const u64 open[1] = {1};
  for (int i = 0; i < g; i++) moqssts_t_bp_once(st, sets, 1, open, 0);
}

static void test_moqssts_starts_at_the_lowest_tier(void) {
  moqssts_set s[]    = {moqssts_t_bpset(1, 1)};
  const u64   open[] = {1};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  CHECK(moqssts_t_bp_once(&st, s, 1, open, 0) == 10);
}

static void test_moqssts_rises_one_tier_per_five_clear_groups(void) {
  moqssts_set s[]     = {moqssts_t_bpset(1, 1)};
  const u64   clear[] = {1};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  for (int g = 0; g < 4; g++)
    CHECK(moqssts_t_bp_once(&st, s, 1, clear, 0) == 10);
  CHECK(moqssts_t_bp_once(&st, s, 1, clear, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, clear, 0) == 11);
}

static void test_moqssts_falls_one_tier_at_the_downshift_depth(void) {
  moqssts_set s[]   = {moqssts_t_bpset(1, 1)};
  const u64   one[] = {1}, two[] = {2};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 10);
  CHECK(moqssts_t_bp_once(&st, s, 1, one, 0) == 12);
  CHECK(moqssts_t_bp_once(&st, s, 1, two, 0) == 11);
}

static void test_moqssts_recovers_as_soon_as_the_streams_are_gone(void) {
  moqssts_set s[]   = {moqssts_t_bpset(1, 1)};
  const u64   one[] = {1}, two[] = {2}, drained[] = {0};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 5);
  CHECK(moqssts_t_bp_once(&st, s, 1, one, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, two, 0) == 10);
  for (int g = 7; g < 11; g++)
    CHECK(moqssts_t_bp_once(&st, s, 1, drained, 0) == 10);
  CHECK(moqssts_t_bp_once(&st, s, 1, drained, 0) == 11);
}

static void test_moqssts_a_timeout_during_cooldown_drops_the_tier_again(void) {
  moqssts_set s[]   = {moqssts_t_bpset(1, 1)};
  const u64   one[] = {1}, two[] = {2};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 15);
  CHECK(moqssts_t_bp_once(&st, s, 1, one, 0) == 12);
  CHECK(moqssts_t_bp_once(&st, s, 1, two, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, one, 1) == 10);
}

static void test_moqssts_rising_depth_during_cooldown_drops_after_two(void) {
  moqssts_set s[]  = {moqssts_t_bpset(1, 1)};
  const u64   d1[] = {1}, d2[] = {2}, d3[] = {3}, d4[] = {4};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 15);
  CHECK(moqssts_t_bp_once(&st, s, 1, d1, 0) == 12);
  CHECK(moqssts_t_bp_once(&st, s, 1, d2, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, d3, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, d4, 0) == 10);
}

static void test_moqssts_steady_depth_during_cooldown_never_drops_further(
    void) {
  moqssts_set s[]   = {moqssts_t_bpset(1, 1)};
  const u64   two[] = {2};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 15);
  moqssts_t_bp_once(&st, s, 1, two, 0);
  for (int g = 16; g < 25; g++)
    CHECK(moqssts_t_bp_once(&st, s, 1, two, 0) == 11);
}

static void test_moqssts_never_drops_below_the_lowest_tier(void) {
  moqssts_set s[]    = {moqssts_t_bpset(1, 1)};
  const u64   nine[] = {9};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  for (u64 g = 0; g < 20; g++)
    CHECK(moqssts_t_bp_once(&st, s, 1, nine, g * 3) == 10);
}

static void test_moqssts_bp_an_inactive_set_forwards_nothing(void) {
  moqssts_set s[]    = {moqssts_t_bpset(1, 0), moqssts_t_bpset(2, 1)};
  const u64   open[] = {4, 0};
  int         out[2] = {0};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_bp_decide(&st, s, 2, open, 0, out);
  CHECK(moqssts_t_track(&s[0], out[0]) == MOQSSTS_T_NONE);
  CHECK(moqssts_t_track(&s[1], out[1]) == 20);
}

static void test_moqssts_every_active_set_moves_to_the_same_tier(void) {
  moqssts_set s[]     = {moqssts_t_bpset(1, 1), moqssts_t_bpset(2, 1)};
  const u64   clear[] = {1, 0};
  int         out[2]  = {0};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  for (int g = 0; g < 5; g++) moqssts_t_bp_once(&st, s, 2, clear, 0);
  moqssts_bp_decide(&st, s, 2, clear, 0, out);
  CHECK(moqssts_t_track(&s[0], out[0]) == 11);
  CHECK(moqssts_t_track(&s[1], out[1]) == 21);
}

static void test_moqssts_two_active_sets_are_pinned_to_the_lowest_tier(void) {
  moqssts_set s[]        = {moqssts_t_bpset(1, 1), moqssts_t_bpset(2, 1)};
  const u64   one_each[] = {1, 1};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  for (int g = 0; g < 30; g++)
    CHECK(moqssts_t_bp_once(&st, s, 2, one_each, 0) == 10);
}

static void test_moqssts_the_tier_is_capped_by_the_longest_ladder(void) {
  moqssts_set s[]   = {moqssts_t_bpset(1, 1)};
  const u64   one[] = {1}, two[] = {2};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 40);
  CHECK(moqssts_t_bp_once(&st, s, 1, one, 0) == 12);
  CHECK(moqssts_t_bp_once(&st, s, 1, two, 0) == 11);
}

static void test_moqssts_instances_do_not_share_state(void) {
  moqssts_set s[]     = {moqssts_t_bpset(1, 1)};
  const u64   clear[] = {1};
  moqssts_bp  first, second;
  moqssts_bp_init(&first);
  moqssts_bp_init(&second);
  for (int g = 0; g < 20; g++) moqssts_t_bp_once(&first, s, 1, clear, 0);
  CHECK(moqssts_t_bp_once(&second, s, 1, clear, 0) == 10);
}

static void test_moqssts_cooldown_brackets_the_settle_down_period(void) {
  moqssts_bp st;
  moqssts_bp_init(&st);
  for (int g = 0; g < 5; g++) moqssts_bp_observe(&st, moqssts_obs_make(1, 0));
  CHECK(st.tier == 1);
  CHECK(!st.in_cooldown);
  moqssts_bp_observe(&st, moqssts_obs_make(2, 0));
  CHECK(st.tier == 0);
  CHECK(st.in_cooldown);
  moqssts_bp_observe(&st, moqssts_obs_make(1, 0));
  CHECK(!st.in_cooldown);
}

static void test_moqssts_a_timeout_counts_as_depth_and_as_evidence(void) {
  moqssts_obs ob = moqssts_obs_make(1, 2);
  CHECK(ob.depth == 3);
  CHECK(ob.timed_out);
  CHECK(!moqssts_obs_make(1, 0).timed_out);
}

/* lib.rs active_stream_depth: only sets with a subscriber count. */
static void test_moqssts_active_depth_counts_active_sets_only(void) {
  moqssts_set s[] = {
      moqssts_t_bpset(1, 1), moqssts_t_bpset(2, 0), moqssts_t_bpset(3, 1)};
  const u64 open[] = {2, 7, 3};
  CHECK(moqssts_active_depth(s, 3, open) == 5);
  CHECK(moqssts_active_depth(s, 0, open) == 0);
}

/* ===== registry.rs ===== */

static void test_moqssts_unknown_ids_are_rejected(void) {
  CHECK(!moqssts_alg_supported(12345));
}

static void test_moqssts_the_default_algorithm_is_always_available(void) {
  CHECK(moqssts_alg_supported(MOQSSTS_ALG_DEFAULT));
  CHECK(moqssts_alg_supported(MOQSSTS_ALG_BACKPRESSURE));
}

/* ===== derived: review round 1 ===== */

/* More sets than the cap: the first MOQSSTS_MAX_SETS are decided, the rest
 * are answered MOQSSTS_NONE rather than left unwritten. */
static void test_moqssts_sets_past_the_cap_forward_nothing(void) {
  static const moqssts_t_pair l[] = {{500, 1}};
  moqssts_set                 s[MOQSSTS_MAX_SETS + 1];
  u64                         open[MOQSSTS_MAX_SETS + 1] = {0};
  int                         out[MOQSSTS_MAX_SETS + 1];
  moqssts_bp                  st;
  for (usz i = 0; i <= MOQSSTS_MAX_SETS; i++) {
    s[i]   = moqssts_t_set(i + 1, 0, 1, 1, l, 1);
    out[i] = 99;
  }
  moqssts_default_decide(~0ULL, s, MOQSSTS_MAX_SETS + 1, out);
  CHECK(out[0] == 0);
  CHECK(out[MOQSSTS_MAX_SETS - 1] == 0);
  CHECK(out[MOQSSTS_MAX_SETS] == MOQSSTS_NONE);
  for (usz i = 0; i <= MOQSSTS_MAX_SETS; i++) out[i] = 99;
  moqssts_bp_init(&st);
  moqssts_bp_decide(&st, s, MOQSSTS_MAX_SETS + 1, open, 0, out);
  CHECK(out[0] == 0);
  CHECK(out[MOQSSTS_MAX_SETS] == MOQSSTS_NONE);
  CHECK(MOQSSTS_MAX_SETS >= 31);
}

/* state.rs observe_cooldown records the depth of every cooldown group:
 * 2 -> 4 -> 3 is one rise then a fall, so the tier holds. */
static void test_moqssts_cooldown_reference_follows_every_group(void) {
  moqssts_set s[]  = {moqssts_t_bpset(1, 1)};
  const u64   d2[] = {2}, d3[] = {3}, d4[] = {4};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 10);
  CHECK(moqssts_t_bp_once(&st, s, 1, d2, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, d4, 0) == 11);
  CHECK(moqssts_t_bp_once(&st, s, 1, d3, 0) == 11);
}

/* allocate.rs: a rank's spend leaves `remaining` before the next rank. */
static void test_moqssts_a_rank_spend_leaves_the_budget(void) {
  static const moqssts_t_pair a[] = {{1000, 10}};
  static const moqssts_t_pair b[] = {{500, 20}, {1500, 21}};
  moqssts_set                 s[] = {
      moqssts_t_set(1, 0, 1, 1, a, 1), moqssts_t_set(2, 1, 1, 1, b, 2)};
  CHECK(moqssts_t_alloc(2000, s, 2, 0) == 10);
  CHECK(moqssts_t_alloc(2000, s, 2, 1) == 20);
}

/* activate is a member count: 2 needs two members. */
static void test_moqssts_activate_counts_members(void) {
  static const moqssts_t_pair l[] = {{500, 10}, {1000, 11}};
  moqssts_set                 s[] = {moqssts_t_set(1, 0, 1, 1, l, 2)};
  s[0].activate                   = 2;
  s[0].n_members                  = 1;
  CHECK(!moqssts_set_active(&s[0]));
  CHECK(moqssts_t_alloc(10000, s, 1, 0) == MOQSSTS_T_NONE);
  s[0].n_members = 2;
  CHECK(moqssts_set_active(&s[0]));
  CHECK(moqssts_t_alloc(10000, s, 1, 0) == 11);
}

/* default/mod.rs: budget min UNLIMITED_KBPS, then saturating_mul by the
 * weight: target = ~0/10 >= ~0/16, so the top member; a wrapping multiply
 * would give (2^63-10)/10 < ~0/16 and pick the lower one. */
static void test_moqssts_unlimited_budget_does_not_overflow(void) {
  static const moqssts_t_pair l[] = {{500, 10}, {~0ULL / 16, 11}};
  moqssts_set                 s[] = {moqssts_t_set(1, 0, 10, 1, l, 2)};
  CHECK(moqssts_t_alloc(~0ULL, s, 1, 0) == 11);
}

/* state.rs Event: Held / Upshift / Downshift / CooldownExit. */
static void test_moqssts_observe_reports_events(void) {
  moqssts_bp st;
  moqssts_bp_init(&st);
  CHECK(moqssts_bp_observe(&st, moqssts_obs_make(2, 0)) == MOQSSTS_EV_HELD);
  for (int g = 0; g < 4; g++)
    CHECK(moqssts_bp_observe(&st, moqssts_obs_make(1, 0)) == MOQSSTS_EV_HELD);
  CHECK(moqssts_bp_observe(&st, moqssts_obs_make(1, 0)) == MOQSSTS_EV_UPSHIFT);
  CHECK(
      moqssts_bp_observe(&st, moqssts_obs_make(2, 0)) == MOQSSTS_EV_DOWNSHIFT);
  CHECK(
      moqssts_bp_observe(&st, moqssts_obs_make(1, 0)) ==
      MOQSSTS_EV_COOLDOWN_EXIT);
}

/* state.rs observe_cooldown: a timeout drops only `if current_index > 0`;
 * at tier 0 it falls through to the depth rule and holds (derived). */
static void test_moqssts_a_timeout_at_the_lowest_tier_holds(void) {
  moqssts_set s[]  = {moqssts_t_bpset(1, 1)};
  const u64   d2[] = {2};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  moqssts_t_climb(&st, s, 5);
  CHECK(moqssts_t_bp_once(&st, s, 1, d2, 0) == 10);
  CHECK(st.in_cooldown);
  CHECK(moqssts_t_bp_once(&st, s, 1, d2, 1) == 10);
  CHECK(st.tier == 0);
}

/* allocate.rs walks every distinct rank, u8 255 included (derived). */
static void test_moqssts_rank_255_is_served(void) {
  static const moqssts_t_pair l[] = {{500, 10}, {1000, 11}};
  moqssts_set                 s[] = {moqssts_t_set(1, 255, 1, 1, l, 2)};
  CHECK(moqssts_t_alloc(10000, s, 1, 0) == 11);
}

/* backpressure/mod.rs: max_index = longest.unwrap_or(1).saturating_sub(1),
 * so with no sets (or only empty ones) the tier is clamped to 0 (derived). */
static void test_moqssts_no_ladder_clamps_the_tier_to_zero(void) {
  moqssts_set s[]     = {moqssts_t_bpset(1, 1)};
  moqssts_set empty[] = {moqssts_t_set(2, 0, 1, 0, 0, 0)};
  const u64   zero[] = {0}, one[] = {1};
  int         out[1] = {99};
  moqssts_bp  st;
  moqssts_bp_init(&st);
  for (int g = 0; g < 5; g++) moqssts_bp_decide(&st, s, 0, zero, 0, out);
  for (int g = 0; g < 5; g++) moqssts_bp_decide(&st, empty, 1, zero, 0, out);
  CHECK(out[0] == MOQSSTS_NONE);
  CHECK(st.tier == 0);
  CHECK(moqssts_t_bp_once(&st, s, 1, one, 0) == 10);
}

void test_moqssts(void) {
  test_moqssts_budget_is_the_stricter_of_estimate_and_cap();
  test_moqssts_single_set_picks_the_highest_affordable_track();
  test_moqssts_two_sets_of_the_same_rank_split_by_weight();
  test_moqssts_a_saturated_set_gives_its_share_back();
  test_moqssts_a_high_rank_is_served_before_a_low_one();
  test_moqssts_default_an_inactive_set_forwards_nothing();
  test_moqssts_a_budget_below_the_lowest_tier_forwards_nothing();
  test_moqssts_a_zero_weight_set_is_never_served();
  test_moqssts_every_set_gets_an_answer();
  test_moqssts_an_empty_set_list_decides_nothing();
  test_moqssts_starts_at_the_lowest_tier();
  test_moqssts_rises_one_tier_per_five_clear_groups();
  test_moqssts_falls_one_tier_at_the_downshift_depth();
  test_moqssts_recovers_as_soon_as_the_streams_are_gone();
  test_moqssts_a_timeout_during_cooldown_drops_the_tier_again();
  test_moqssts_rising_depth_during_cooldown_drops_after_two();
  test_moqssts_steady_depth_during_cooldown_never_drops_further();
  test_moqssts_never_drops_below_the_lowest_tier();
  test_moqssts_bp_an_inactive_set_forwards_nothing();
  test_moqssts_every_active_set_moves_to_the_same_tier();
  test_moqssts_two_active_sets_are_pinned_to_the_lowest_tier();
  test_moqssts_the_tier_is_capped_by_the_longest_ladder();
  test_moqssts_instances_do_not_share_state();
  test_moqssts_cooldown_brackets_the_settle_down_period();
  test_moqssts_a_timeout_counts_as_depth_and_as_evidence();
  test_moqssts_active_depth_counts_active_sets_only();
  test_moqssts_unknown_ids_are_rejected();
  test_moqssts_the_default_algorithm_is_always_available();
  test_moqssts_sets_past_the_cap_forward_nothing();
  test_moqssts_cooldown_reference_follows_every_group();
  test_moqssts_a_rank_spend_leaves_the_budget();
  test_moqssts_activate_counts_members();
  test_moqssts_unlimited_budget_does_not_overflow();
  test_moqssts_observe_reports_events();
  test_moqssts_a_timeout_at_the_lowest_tier_holds();
  test_moqssts_rank_255_is_served();
  test_moqssts_no_ladder_clamps_the_tier_to_zero();
}
