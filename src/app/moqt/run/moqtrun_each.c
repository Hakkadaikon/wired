#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_track_drop_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx, u64 rid);
static void moqtrun_peer_each_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* q,
    moqtrun_track_fn    fn,
    usz                 idx,
    u64                 arg);
static void moqtrun_hub_each_track(
    wired_moqt_hub* hub, moqtrun_track_fn fn, usz idx, u64 arg);
static void moqtrun_reqs_drop(wired_moqt_hub* hub, wired_wt_session* s);
static void moqtrun_peer_frags_release(wired_moqtrun_peer* p);

/* Deactivate track t's subscription entries held by peer index idx under
 * Request ID rid. */
static void moqtrun_track_drop_sub(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz idx, u64 rid) {
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    if (!moqtrun_sub_is_req(&t->subs[si], idx, rid)) {
      continue;
    }
    t->subs[si].active = 0;
    moqtrun_relays_clear_sub(hub, t, si);
  }
}

static void moqtrun_peer_each_track(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* q,
    moqtrun_track_fn    fn,
    usz                 idx,
    u64                 arg) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (q->tracks[t].in_use) {
      fn(hub, &q->tracks[t], idx, arg);
    }
  }
}

/* The hub's own tracks (blob and live) count too: e.g. they forget a
 * closed peer index, so a reconnect landing in the same slot is served
 * afresh, not mistaken for the dead peer. */
static void moqtrun_hub_each_track(
    wired_moqt_hub* hub, moqtrun_track_fn fn, usz idx, u64 arg) {
  if (hub->blob_track.in_use) {
    fn(hub, &hub->blob_track, idx, arg);
  }
  if (hub->live.track.in_use) {
    fn(hub, &hub->live.track, idx, arg);
  }
}

/* fn on every in-use track: every peer's and the hub's own. */
void moqtrun_each_track(
    wired_moqt_hub* hub, moqtrun_track_fn fn, usz idx, u64 arg) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (hub->peers[i].in_use) {
      moqtrun_peer_each_track(hub, &hub->peers[i], fn, idx, arg);
    }
  }
  moqtrun_hub_each_track(hub, fn, idx, arg);
}

/* Deactivate every subscription held for peer index idx under Request ID
 * rid. */
void moqtrun_drop_peer_subs(wired_moqt_hub* hub, usz idx, u64 rid) {
  moqtrun_each_track(hub, moqtrun_track_drop_sub, idx, rid);
}

/* A closed session's request streams go back to the pool. */
static void moqtrun_reqs_drop(wired_moqt_hub* hub, wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_req_owned(&hub->reqs[i], s)) {
      hub->reqs[i].in_use = 0;
    }
  }
}

/* A closed publisher's held fragments can never complete: their buffers
 * go back to the pool (the relay entries themselves stay -- see below). */
static void moqtrun_peer_frags_release(wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
      moqtrun_frag_release_unless_poisoned(&p->tracks[t].relays[r]);
    }
  }
}

void wired_moqt_on_session_close(void* app_ctx, wired_wt_session* s) {
  wired_moqt_hub*     hub = (wired_moqt_hub*)app_ctx;
  wired_moqtrun_peer* p   = moqtrun_find_by_wt(hub, s);
  if (!p) {
    return;
  }
  moqtrun_upf_detach(hub, s); /* first: nothing more is sent toward s */
  moqtrun_peer_tracks_ended(hub, p);
  moqtrun_drop_peer_subs(hub, (usz)(p - hub->peers), MOQTRUN_RID_ANY);
  moqtrun_reqs_drop(hub, s);
  moqtrun_rdv_drop_wt(hub, s);
  moqtrun_fetches_drop(hub, s);
  /* The leaver's own rings return now (moqtrun_rel_drop_ring's doc); its
   * relay entries stay untouched so a later re-claim can still reset the
   * subscriber streams they record (moqtrun_track_reset_stale_relays). */
  moqtrun_peer_drop_rings(hub, p);
  moqtrun_peer_frags_release(p);
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    moqtrun_track_cache_drop(hub, &p->tracks[t]);
  }
  p->in_use = 0;
  moqtrun_reqs_tick(hub); /* its namespaces are withdrawn (10.18) */
}
