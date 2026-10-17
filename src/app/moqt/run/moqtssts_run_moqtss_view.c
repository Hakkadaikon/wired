#include "app/moqt/run/moqtssts_run_impl.h"

static int  moqtss_view_wants(const moqtss_set* st, u64 alg);
static int  moqtss_hold_pick(u64 tier, const moqssts_set* s);
static void moqtss_bp_hold(const moqtss_sess* ss, moqtss_view* v);
static u64  moqtss_est(const wired_moqt_hub* hub, usz sidx);
static void moqtss_view_run(
    const wired_moqt_hub* hub, usz sidx, u64 alg, moqtss_view* v, int pace);
static u64 moqtss_pick_alias(const moqtss_view* v, usz j);
static u64 moqtss_view_pick(const moqtss_view* v, usz k);

static int moqtss_view_wants(const moqtss_set* st, u64 alg) {
  return st->in_use && st->algorithm_id == alg;
}

void moqtss_view_of(
    const wired_moqt_hub* hub, usz sidx, u64 alg, moqtss_view* v) {
  const moqtss_sess* ss = &hub->peers[sidx].ssts;
  v->n                  = 0;
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++) {
    if (moqtss_view_wants(&ss->sets[k], alg)) {
      moqtss_view_add(hub, v, &ss->sets[k], sidx, k);
    }
  }
}

/* A non-pacing backpressure set's pick: the current tier, clamped to its
 * ladder, nothing when inactive (moqssts_bp_decide without observing). */
static int moqtss_hold_pick(u64 tier, const moqssts_set* s) {
  if (!moqssts_set_active(s)) {
    return MOQSSTS_NONE;
  }
  return (int)u64_min(tier, s->n_members - 1);
}

static void moqtss_bp_hold(const moqtss_sess* ss, moqtss_view* v) {
  for (usz j = 0; j < v->n; j++) {
    v->out[j] = moqtss_hold_pick(ss->bp.tier, &v->sets[j]);
  }
}

/* Session sidx's delivery-rate estimate (io.est_kbps), 0 when unknown. */
static u64 moqtss_est(const wired_moqt_hub* hub, usz sidx) {
  return hub->io.est_kbps ? hub->io.est_kbps(hub->peers[sidx].wt) : 0;
}

/* Runs alg over the view (default budget: the stricter of the session's
 * estimate and the cap). The pacing set's backpressure decision observes
 * and consumes the session's reset count; any other backpressure set
 * holds the tier. */
static void moqtss_view_run(
    const wired_moqt_hub* hub, usz sidx, u64 alg, moqtss_view* v, int pace) {
  moqtss_sess* ss = (moqtss_sess*)&hub->peers[sidx].ssts;
  if (alg != MOQSSTS_ALG_BACKPRESSURE) {
    moqssts_default_decide(
        moqssts_budget_kbps(moqtss_est(hub, sidx), hub->ssts_cap_kbps), v->sets,
        v->n, v->out);
    return;
  }
  if (!pace) {
    moqtss_bp_hold(ss, v);
    return;
  }
  moqssts_bp_decide(&ss->bp, v->sets, v->n, v->open, ss->timeouts, v->out);
  ss->timeouts = 0;
}

static u64 moqtss_pick_alias(const moqtss_view* v, usz j) {
  if (v->out[j] < 0) {
    return MOQTSS_PICK_NONE;
  }
  return v->sets[j].m[v->out[j]].track_id;
}

/* The view's pick for set slot k (NONE when k was not in the view: an
 * algorithm no session list owns, controller.rs "unowned"). */
static u64 moqtss_view_pick(const moqtss_view* v, usz k) {
  for (usz j = 0; j < v->n; j++) {
    if (v->slot[j] == k) {
      return moqtss_pick_alias(v, j);
    }
  }
  return MOQTSS_PICK_NONE;
}

/* Decides group g for set slot k now (one algorithm run, joint over the
 * session's sets of k's algorithm) and records it: final for (k, g).
 * Backpressure observes only when pace is set. */
u64 moqtss_decide_as(wired_moqt_hub* hub, usz sidx, usz k, u64 g, int pace) {
  moqtss_sess* ss = &hub->peers[sidx].ssts;
  moqtss_view  v;
  moqtss_prune(hub, sidx);
  moqtss_view_of(hub, sidx, ss->sets[k].algorithm_id, &v);
  moqtss_view_run(hub, sidx, ss->sets[k].algorithm_id, &v, pace);
  u64 pick = moqtss_view_pick(&v, k);
  moqtss_ring_record(&ss->sets[k], g, pick);
  return pick;
}
