#include "app/moqt/run/moqtssts_run_impl.h"

static u64  moqtss_decide(wired_moqt_hub* hub, usz sidx, usz k, u64 g);
static void moqtss_tick_observe(wired_moqt_hub* hub, usz sidx, u64 now_ms);
static void moqtss_tick_arm(moqtss_sess* ss, u64 now_ms);
static void moqtss_tick_paced(wired_moqt_hub* hub, usz sidx, u64 now_ms);
static void moqtss_tick_sess(wired_moqt_hub* hub, usz sidx, u64 now_ms);
static int  moqtss_ticks(const wired_moqtrun_peer* p);
static u16  moqtss_shr(u16 v, u64 k);

/* A group's first arrival: the pacing set observes. */
static u64 moqtss_decide(wired_moqt_hub* hub, usz sidx, usz k, u64 g) {
  return moqtss_decide_as(
      hub, sidx, k, g, moqtss_pacer(&hub->peers[sidx].ssts) == (int)k);
}

/* The alias set slot k forwards for group g, deciding g now if needed. */
u64 moqtss_pick(wired_moqt_hub* hub, usz sidx, usz k, u64 g) {
  const moqtss_dec* e = moqtss_ring_find(&hub->peers[sidx].ssts.sets[k], g);
  return e ? e->pick : moqtss_decide(hub, sidx, k, g);
}

/* ===== tick observation (controller.rs DECISION_INTERVAL) ===== */

/* One observation over the session's backpressure sets: moqssts_bp_decide
 * observes depth + resets and clamps the tier; the picks are not recorded
 * (each group is still decided at its first arrival). */
static void moqtss_tick_observe(wired_moqt_hub* hub, usz sidx, u64 now_ms) {
  moqtss_sess* ss = &hub->peers[sidx].ssts;
  moqtss_view  v;
  moqtss_view_of(hub, sidx, MOQSSTS_ALG_BACKPRESSURE, &v);
  moqssts_bp_decide(&ss->bp, v.sets, v.n, v.open, ss->timeouts, v.out);
  ss->timeouts    = 0;
  ss->next_obs_ms = now_ms + MOQTSS_OBS_MS;
}

static void moqtss_tick_arm(moqtss_sess* ss, u64 now_ms) {
  ss->obs_armed   = 1;
  ss->next_obs_ms = now_ms + MOQTSS_OBS_MS;
}

/* Armed: observes when due. Not yet: this tick only arms. */
static void moqtss_tick_paced(wired_moqt_hub* hub, usz sidx, u64 now_ms) {
  moqtss_sess* ss = &hub->peers[sidx].ssts;
  if (!ss->obs_armed) {
    moqtss_tick_arm(ss, now_ms);
    return;
  }
  if (now_ms >= ss->next_obs_ms) {
    moqtss_tick_observe(hub, sidx, now_ms);
  }
}

static void moqtss_tick_sess(wired_moqt_hub* hub, usz sidx, u64 now_ms) {
  moqtss_prune(hub, sidx);
  if (moqtss_pacer(&hub->peers[sidx].ssts) >= 0) {
    moqtss_tick_paced(hub, sidx, now_ms);
  }
}

static int moqtss_ticks(const wired_moqtrun_peer* p) {
  return p->in_use && p->ssts.algs;
}

void moqtss_tick(wired_moqt_hub* hub, u64 now_ms) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtss_ticks(&hub->peers[i])) {
      moqtss_tick_sess(hub, i, now_ms);
    }
  }
}

/* ===== per-subscription verdict window ===== */

static u16 moqtss_shr(u16 v, u64 k) {
  return k >= MOQTSS_WIN ? 0 : (u16)(v >> k);
}

/* g past the window's top: slide it up so g is its last bit. */
void moqtss_rebase_up(wired_moqtrun_sub* s, u64 g) {
  if (g < s->ssts_base + MOQTSS_WIN) {
    return;
  }
  u64 k         = g - (MOQTSS_WIN - 1) - s->ssts_base;
  s->ssts_known = moqtss_shr(s->ssts_known, k);
  s->ssts_fwd   = moqtss_shr(s->ssts_fwd, k);
  s->ssts_base  = g - (MOQTSS_WIN - 1);
}

/* g below the window (a late older group): slide it down to g. */
void moqtss_rebase_down(wired_moqtrun_sub* s, u64 g) {
  if (g >= s->ssts_base) {
    return;
  }
  u64 k         = s->ssts_base - g;
  s->ssts_known = (u16)(s->ssts_known << k);
  s->ssts_fwd   = (u16)(s->ssts_fwd << k);
  s->ssts_base  = g;
}

/* g below the window fits only while no recorded verdict would be pushed
 * out of the top. */
int moqtss_below_fits(const wired_moqtrun_sub* s, u64 g) {
  u64 k = s->ssts_base - g;
  return k < MOQTSS_WIN && (s->ssts_known >> (MOQTSS_WIN - k)) == 0;
}
