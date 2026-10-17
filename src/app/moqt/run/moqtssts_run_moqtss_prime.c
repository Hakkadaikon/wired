#include "app/moqt/run/moqtssts_run_impl.h"

static int  moqtss_stampable(const wired_moqtrun_sub* s, u64 g);
static void moqtss_stamp(wired_moqtrun_sub* s, u64 g, int fwd);
static u32  moqtss_bit_of(const wired_moqtrun_sub* s, u64 g);
static int  moqtss_primes(const wired_moqtrun_sub* s);
static void moqtss_prime_sub(wired_moqt_hub* hub, wired_moqtrun_sub* s, u64 g);
static int  moqtss_in_window(const moqtss_set* st, u64 g);
static u64  moqtss_pick_held(wired_moqt_hub* hub, usz sidx, usz k, u64 g);
static void moqtss_join_prime_k(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, int k, u64 g);

/* A stamp below a window it cannot shift is dropped: the newest verdicts
 * stay, and the late group is not forwarded. */
static int moqtss_stampable(const wired_moqtrun_sub* s, u64 g) {
  return g >= s->ssts_base || moqtss_below_fits(s, g);
}

static void moqtss_stamp(wired_moqtrun_sub* s, u64 g, int fwd) {
  if (!s->ssts_known) {
    s->ssts_base = g;
  }
  if (!moqtss_stampable(s, g)) {
    return;
  }
  moqtss_rebase_up(s, g);
  moqtss_rebase_down(s, g);
  u16 bit       = (u16)(1u << (g - s->ssts_base));
  s->ssts_known = (u16)(s->ssts_known | bit);
  s->ssts_fwd   = (u16)((s->ssts_fwd & ~bit) | (bit * (fwd != 0)));
}

static u32 moqtss_bit_of(const wired_moqtrun_sub* s, u64 g) {
  return g >= s->ssts_base && g - s->ssts_base < MOQTSS_WIN
             ? 1u << (g - s->ssts_base)
             : 0;
}

int moqtss_sub_pass(const wired_moqtrun_sub* s, u64 g) {
  if (!s->ssts_on) {
    return 1;
  }
  return (moqtss_bit_of(s, g) & s->ssts_known & s->ssts_fwd) != 0;
}

/* ===== the gate's entry (subscription.rs ssts_gate_allows) ===== */

static int moqtss_primes(const wired_moqtrun_sub* s) {
  return s->active && s->ssts_on;
}

/* s's verdict for g. k < 0 (a member whose set is gone) is unreachable:
 * a re-attached subscription (a re-PUBLISH, a new path after its
 * upstream ended) leaves its set first (moqtss_sub_leave); were it
 * reached, s is stamped "not this group" and stays gated rather than
 * forwarding everything. */
static void moqtss_prime_sub(wired_moqt_hub* hub, wired_moqtrun_sub* s, u64 g) {
  if (!moqtss_primes(s)) {
    return;
  }
  int k = moqtss_set_of_alias(&hub->peers[s->session_idx].ssts, s->track_alias);
  u64 pick =
      k < 0 ? MOQTSS_PICK_NONE : moqtss_pick(hub, s->session_idx, (usz)k, g);
  moqtss_stamp(s, g, pick == s->track_alias);
}

/* Group g is inside set st's decision window, or st decided nothing yet:
 * an older g's decision is pruned, and deciding it again would break
 * "one decision per group". */
static int moqtss_in_window(const moqtss_set* st, u64 g) {
  return !st->has_largest || g + WIRED_MOQTRUN_SSTS_KEEP >= st->largest;
}

/* A join is no group arrival: the recorded decision, else one made with
 * the tier held (backpressure does not observe). */
static u64 moqtss_pick_held(wired_moqt_hub* hub, usz sidx, usz k, u64 g) {
  const moqtss_dec* e = moqtss_ring_find(&hub->peers[sidx].ssts.sets[k], g);
  return e ? e->pick : moqtss_decide_as(hub, sidx, k, g, 0);
}

static void moqtss_join_prime_k(
    wired_moqt_hub* hub, wired_moqtrun_sub* s, int k, u64 g) {
  moqtss_sess* ss = &hub->peers[s->session_idx].ssts;
  if (k < 0 || !moqtss_in_window(&ss->sets[k], g)) {
    return;
  }
  u64 pick = moqtss_pick_held(hub, s->session_idx, (usz)k, g);
  moqtss_stamp(s, g, pick == s->track_alias);
}

/* s just joined while group g is in flight: s's verdict for g now. */
void moqtss_join_prime(wired_moqt_hub* hub, wired_moqtrun_sub* s, u64 g) {
  if (!moqtss_primes(s)) {
    return;
  }
  moqtss_join_prime_k(
      hub, s,
      moqtss_set_of_alias(&hub->peers[s->session_idx].ssts, s->track_alias), g);
}

void moqtss_prime(wired_moqt_hub* hub, wired_moqtrun_track* track, u64 g) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    moqtss_prime_sub(hub, &track->subs[i], g);
  }
}
