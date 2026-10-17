#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_upd_fits(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params,
    u8                         was_off);
static int moqtrun_ssts_peer_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static int  moqtrun_relay_holds(const wired_moqtrun_relay* rl, usz i);
static void moqtrun_relays_resched(
    wired_moqt_hub*            hub,
    wired_wt_session*          wt,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   s);
static int moqtrun_fill_of(const wired_moqtrun_fetch* f, u64 rid);
static int moqtrun_fill_open_of(
    const wired_moqtrun_fetch* f, const wired_wt_session* wt, u64 rid);
static void moqtrun_fills_resched(
    wired_moqt_hub* hub, const wired_wt_session* wt, u64 rid);

/* 1 iff the applied update s can stand: its fill has room (decided
 * before REQUEST_OK, moqtrun_fill_room) and a FORWARD 0 -> 1 blob send
 * is accepted. */
static int moqtrun_upd_fits(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params,
    u8                         was_off) {
  if (!moqtrun_fill_room(hub, t, s, params)) return 0;
  if (!moqtrun_upd_turned_on(was_off, s, t)) return 1;
  return moqtrun_upd_forward_on(hub, p, s, t);
}

/* All or nothing: a fill without room or a refused blob send restores
 * the whole subscription as it was and fails the update. */
int moqtrun_upd_apply(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    wired_moqtrun_sub*         s,
    const wired_moqtrun_track* t,
    const moqctl_params*       params) {
  wired_moqtrun_sub before = *s;
  moqtrun_upd_params(s, t, params);
  if (moqtrun_upd_fits(hub, p, s, t, params, before.forward_off)) return 1;
  *s = before;
  return 0;
}

/* SSTS (moqtssts_run.c): t is a peer's track, not the hub's blob / live;
 * none (t 0) while the subscription waits for a new path. */
static int moqtrun_ssts_peer_track(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return t && t != &hub->blob_track && t != &hub->live.track;
}

/* SSTS (moqtssts_run.c): a switching set holds subscriptions SUBSCRIBEd
 * to a peer's track -- not the hub's own tracks, nor a subscription the
 * hub PUBLISHed (SUBSCRIBE_TRACKS; moqtail's PUBLISH_OK assignment is not
 * supported), nor one waiting for a new path (its re-attach leaves the
 * set: moqtrun_reattach_one_sub). */
int moqtrun_ssts_settable(
    const wired_moqt_hub*      hub,
    const wired_moqtrun_peer*  p,
    const wired_moqtrun_track* t) {
  return moqtrun_ssts_peer_track(hub, t) && !(p->req && p->req->pub_origin_rid);
}

/* relay rl has an open stream for sub slot i. */
static int moqtrun_relay_holds(const wired_moqtrun_relay* rl, usz i) {
  return rl->in_use && rl->sub_stream_set[i];
}

/* Re-classes every keep-open relay stream of s (slot of t) on wt. */
static void moqtrun_relays_resched(
    wired_moqt_hub*            hub,
    wired_wt_session*          wt,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   s) {
  usz i = (usz)(s - t->subs);
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    const wired_moqtrun_relay* rl = &t->relays[r];
    if (!moqtrun_relay_holds(rl, i)) continue;
    wired_wt_sched k =
        moqtrun_sub_key(s, rl->pub_prio, rl->group_id, rl->subgroup_id);
    moqtrun_sched_apply(hub, wt, (i64)rl->sub_stream_id[i], &k);
  }
}

static int moqtrun_fill_of(const wired_moqtrun_fetch* f, u64 rid) {
  return f->is_fill && f->owner_rid == rid;
}

/* f is subscription {wt, rid}'s fill with its stream open. */
static int moqtrun_fill_open_of(
    const wired_moqtrun_fetch* f, const wired_wt_session* wt, u64 rid) {
  return moqtrun_fetch_owned(f, wt) && f->opened && moqtrun_fill_of(f, rid);
}

/* Re-classes subscription {wt, rid}'s open fill streams. */
static void moqtrun_fills_resched(
    wired_moqt_hub* hub, const wired_wt_session* wt, u64 rid) {
  for (usz j = 0; j < WIRED_MOQTRUN_MAX_FETCHES; j++)
    if (moqtrun_fill_open_of(&hub->fetches[j], wt, rid))
      moqtrun_fetch_sched(hub, &hub->fetches[j]);
}

/* An applied update re-classes the subscription's streams still open
 * (7.1: a changed Subscriber Priority SHOULD reach objects not yet
 * scheduled); later opens read the new value anyway. ponytail: one-shot
 * streams the hub no longer tracks keep their old class until done. */
void moqtrun_upd_resched(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_track* t) {
  if (!t) return;
  moqtrun_relays_resched(hub, p->wt, t, s);
  moqtrun_fills_resched(hub, p->wt, s->request_id);
}
