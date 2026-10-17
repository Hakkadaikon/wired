#include "app/moqt/run/moqtssts_run_impl.h"

static void moqtss_join_at(
    wired_moqt_hub*            hub,
    wired_moqtrun_sub*         s,
    const moqctl_ssa*          a,
    const wired_moqtrun_track* t);
static u64 moqtss_upd_verdict(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a,
    int                      settable);
static int moqtss_peer_is(const wired_moqtrun_peer* p, wired_wt_session* wt);
static int moqtss_active(const moqtss_set* st);
static int moqtss_paces(const moqtss_set* st);

/* A member joining mid-Group gets that Group's verdict now (its recorded
 * decision, else one made now) instead of waiting for the next Group. */
static void moqtss_join_at(
    wired_moqt_hub*            hub,
    wired_moqtrun_sub*         s,
    const moqctl_ssa*          a,
    const wired_moqtrun_track* t) {
  moqtss_join(hub, s, a);
  if (t && t->has_largest) moqtss_join_prime(hub, s, t->largest.group);
}

u64 moqtss_on_subscribe(
    wired_moqt_hub*            hub,
    wired_moqtrun_sub*         s,
    const moqctl_params*       params,
    const wired_moqtrun_track* t) {
  const moqctl_ssa* a = moqtss_ssa_of(params);
  moqtss_sub_reset(s);
  moqtss_leave(&hub->peers[s->session_idx].ssts, s->track_alias);
  if (!a) return MOQTSS_ACCEPT;
  u64 code = moqtss_check(hub, s, params, a);
  if (code == MOQTSS_ACCEPT) moqtss_join_at(hub, s, a, t);
  return code;
}

static u64 moqtss_upd_verdict(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    const moqctl_ssa*        a,
    int                      settable) {
  if (!settable) return MOQCTL_ERR_UNSUPPORTED_EXTENSION;
  return moqtss_check(hub, s, params, a);
}

u64 moqtss_upd_check(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params,
    int                      settable,
    u64                      prior) {
  const moqctl_ssa* a = moqtss_ssa_of(params);
  if (prior != MOQTSS_ACCEPT || !a) return prior;
  return moqtss_upd_verdict(hub, s, params, a, settable);
}

void moqtss_on_update(
    wired_moqt_hub*            hub,
    wired_moqtrun_sub*         s,
    const moqctl_params*       params,
    const wired_moqtrun_track* t) {
  const moqctl_ssa* a = moqtss_ssa_of(params);
  if (a) moqtss_join_at(hub, s, a, t);
}

int moqtss_sub_in_set(const wired_moqtrun_sub* s) { return s->ssts_on; }

/* ===== congestion evidence (client.rs StreamTimeout) ===== */

static int moqtss_peer_is(const wired_moqtrun_peer* p, wired_wt_session* wt) {
  return p->in_use && p->wt == wt;
}

static int moqtss_active(const moqtss_set* st) {
  return st->activate > 0 && st->n >= st->activate;
}

static int moqtss_paces(const moqtss_set* st) {
  return st->in_use && st->algorithm_id == MOQSSTS_ALG_BACKPRESSURE &&
         moqtss_active(st);
}

/* The session's pacing set: its lowest-slot active backpressure set, the
 * one whose decisions advance the tier (-1: none). */
int moqtss_pacer(const moqtss_sess* ss) {
  for (usz k = 0; k < WIRED_MOQTRUN_SSTS_SETS; k++)
    if (moqtss_paces(&ss->sets[k])) return (int)k;
  return -1;
}

/* Counted only while a pacing set exists to consume it: no stale
 * evidence for a backpressure set that becomes active later. */
void moqtss_note_shed(wired_moqt_hub* hub, wired_wt_session* wt) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtss_peer_is(&hub->peers[i], wt))
      hub->peers[i].ssts.timeouts += moqtss_pacer(&hub->peers[i].ssts) >= 0;
}
