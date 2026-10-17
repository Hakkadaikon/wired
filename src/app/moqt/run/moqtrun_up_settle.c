#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_up_cancel(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_up*    u,
    wired_moqtrun_track* t);
static int moqtrun_up_any_sub(const wired_moqtrun_track* t);
static int moqtrun_up_wanted(
    wired_moqt_hub*            hub,
    const wired_moqtrun_up*    u,
    const wired_moqtrun_track* t);
static int moqtrun_up_gone(
    const wired_moqtrun_up* u, const wired_moqtrun_track* t);
static void moqtrun_up_settle(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u);
static void moqtrun_up_settle_open(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u);
static void moqtrun_up_sweep_one(wired_moqt_hub* hub, wired_moqtrun_up* u);

/* Nobody downstream left: the request is cancelled and its track (if
 * Established) retired, so no Object is relayed to no one (NoLeak). */
static void moqtrun_up_cancel(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  pp,
    wired_moqtrun_up*    u,
    wired_moqtrun_track* t) {
  moqtrun_up_reset(hub, pp, u);
  if (t) moqtrun_track_retire(hub, t);
  u->in_use = 0;
}

/* The track ended (PUBLISH_DONE relayed: the hub's side FINs) or was
 * taken over (a PUBLISH of the same name: cancelled). */
void moqtrun_up_end(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u) {
  if (u->done)
    hub->io.stream_fin(u->wt, u->stream_id);
  else
    moqtrun_up_reset(hub, pp, u);
  u->in_use = 0;
}

static int moqtrun_up_any_sub(const wired_moqtrun_track* t) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++)
    if (t->subs[si].active) return 1;
  return 0;
}

/* Someone downstream still wants u: a waiter, or a subscription on its
 * track. */
static int moqtrun_up_wanted(
    wired_moqt_hub*            hub,
    const wired_moqtrun_up*    u,
    const wired_moqtrun_track* t) {
  return moqtrun_up_waiters(hub, moqtrun_up_key(u)) ||
         (t && moqtrun_up_any_sub(t));
}

static int moqtrun_up_gone(
    const wired_moqtrun_up* u, const wired_moqtrun_track* t) {
  return u->track_tag && !t;
}

static void moqtrun_up_settle(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u) {
  wired_moqtrun_track* t = moqtrun_up_track(pp, u);
  if (moqtrun_up_gone(u, t)) {
    moqtrun_up_end(hub, pp, u);
    return;
  }
  if (!moqtrun_up_wanted(hub, u, t)) moqtrun_up_cancel(hub, pp, u, t);
}

/* A publisher session the hub is closing keeps u, untouched, until the
 * close lands: wired_moqt_on_session_close then ends its track through u
 * (a wait for a new path, as for the publisher's own close). */
static void moqtrun_up_settle_open(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u) {
  if (!pp->closing) moqtrun_up_settle(hub, pp, u);
}

/* A publisher session gone takes u with it, no io (NoLeakOnClose); its
 * track already ended for every subscriber. */
static void moqtrun_up_sweep_one(wired_moqt_hub* hub, wired_moqtrun_up* u) {
  wired_moqtrun_peer* pp;
  if (!u->in_use) return;
  pp = moqtrun_find_by_wt(hub, u->wt);
  if (!pp) {
    u->in_use = 0;
    return;
  }
  moqtrun_up_settle_open(hub, pp, u);
}

void moqtrun_up_sync(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++)
    moqtrun_up_sweep_one(hub, &hub->ups[i]);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    moqtrun_up_wait_one(hub, &hub->rdv[i]);
}

/* ----- the publisher's replies on the hub's stream ----- */

/* SUBSCRIBE_OK: the track is claimed on pp under the publisher's Track
 * Alias, as a PUBLISH would claim it, then every waiter proceeds. No
 * slot (the publisher's WIRED_MOQTRUN_MAX_TRACKS_PER_PEER are taken):
 * the waiters are refused EXCESSIVE_LOAD and the request cancelled. */
void moqtrun_up_claim(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        pp,
    wired_moqtrun_up*          u,
    const moqctl_subscribe_ok* m) {
  usz                  pi = (usz)(pp - hub->peers);
  moqtrun_key          k  = moqtrun_up_key(u);
  wired_moqtrun_track* t  = moqtrun_publish_slot(hub, pp, pi, k);
  if (!t) {
    moqtrun_up_refuse_waiters(hub, k, MOQCTL_ERR_EXCESSIVE_LOAD);
    moqtrun_up_cancel(hub, pp, u, 0);
    return;
  }
  moqtrun_track_open(
      hub, t, k, m->track_alias, &m->params, m->track_properties,
      u->request_id);
  u->track_tag = t->cache_tag;
  moqtrun_reattach_subs(hub, t, pi, k);
  moqtrun_rdv_resolve(hub, t, k);
  moqtrun_early_replay(hub, pp);
}
