#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_subscribe_fresh(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    usz                     peer_idx,
    moqtrun_key             k,
    const moqctl_subscribe* m);
static int moqtrun_sw_refused(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   held,
    usz                        peer_idx,
    const moqctl_subscribe*    m);
static int moqtrun_up_pub_open(wired_moqt_hub* hub, const wired_moqtrun_up* u);
static int moqtrun_up_rideable(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqtrun_key k);
static int moqtrun_rdv_wanted(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* p,
    const moqctl_subscribe*   m,
    moqtrun_key               k);

/* A SUBSCRIBE for a track this peer already subscribes: draft-18 6.3
 * allows one subscription per Track and role, so it is refused with
 * DUPLICATE_SUBSCRIPTION; draft-19/22 allow several, and the hub
 * re-answers SUBSCRIBE_OK with the held alias instead of eating another
 * slot (the client resends SUBSCRIBE until a chunk arrives). 1 when held
 * was answered either way, 0 when there is nothing held. */
int moqtrun_sub_held_reply(
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* t,
    const wired_moqtrun_sub*   held) {
  if (!held) return 0;
  if (moqver_caps(p->ver) & MOQVER_CAP_DUP_SUBSCRIPTION)
    moqtrun_send_request_error(p, MOQCTL_ERR_DUPLICATE_SUBSCRIPTION);
  else
    moqtrun_queue_subscribe_ok(p, t, held);
  return 1;
}

/* SUBSCRIBE for the hub's own blob track: a held subscription is
 * re-answered (moqtrun_sub_held_reply), anyone else gets the blob now. */
void moqtrun_subscribe_blob(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* held =
      moqtrun_track_sub_of_peer(&hub->blob_track, peer_idx);
  if (moqtrun_sub_held_reply(p, &hub->blob_track, held)) return;
  moqtrun_blob_send_first(hub, p, peer_idx, m);
}

/* A fresh slot for the SUBSCRIBE, or DOES_NOT_EXIST once the table is
 * full. */
static void moqtrun_subscribe_fresh(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    usz                     peer_idx,
    moqtrun_key             k,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* slot = moqtrun_sub_slot(track);
  if (!slot) {
    moqtrun_send_request_error(p, MOQCTL_ERR_DOES_NOT_EXIST);
    return;
  }
  moqtrun_accept_subscribe(hub, p, track, slot, peer_idx, m, k);
}

/* SWITCH_FROM (moqtswitch.c): an invalid switch is refused before
 * anything is created (INVALID_SWITCH). 1 when refused. */
static int moqtrun_sw_refused(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        p,
    const wired_moqtrun_track* track,
    const wired_moqtrun_sub*   held,
    usz                        peer_idx,
    const moqctl_subscribe*    m) {
  u64 code = moqtsw_check(
      hub, moqtrun_sw_ops(), peer_idx, track, held, m->request_id, &m->params);
  if (code == MOQTSW_ACCEPT) return 0;
  moqtrun_send_request_error(p, code);
  return 1;
}

/* SUBSCRIBE on a found peer track: a SWITCH_FROM is checked first
 * (moqtrun_sw_refused), a held subscription is re-answered
 * (moqtrun_sub_held_reply), anyone else gets a fresh slot. */
void moqtrun_subscribe_peer_track(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    wired_moqtrun_track*    track,
    usz                     peer_idx,
    moqtrun_key             k,
    const moqctl_subscribe* m) {
  wired_moqtrun_sub* held = moqtrun_track_sub_of_peer(track, peer_idx);
  if (moqtrun_sw_refused(hub, p, track, held, peer_idx, m)) return;
  if (moqtrun_sub_held_reply(p, track, held)) return;
  moqtrun_subscribe_fresh(hub, p, track, peer_idx, k, m);
}

/* RENDEZVOUS_TIMEOUT in ms; absent reads 0, its default (10.2.6). */
u64 moqtrun_rdv_rt(const moqctl_subscribe* m) {
  return moqtrun_param_vi(
      moqtrun_sub_param(m, MOQCTL_PARAM_RENDEZVOUS_TIMEOUT));
}

/* u's publisher session is not being closed by the hub. */
static int moqtrun_up_pub_open(wired_moqt_hub* hub, const wired_moqtrun_up* u) {
  return moqtrun_rdv_peer_open(moqtrun_find_by_wt(hub, u->wt));
}

/* An upstream SUBSCRIBE for k that p's SUBSCRIBE may ride: not one to p's
 * own session (its own announcement never serves it), nor one to a
 * session the hub is closing (it would wait for that close). */
static int moqtrun_up_rideable(
    wired_moqt_hub* hub, const wired_moqtrun_peer* p, moqtrun_key k) {
  const wired_moqtrun_up* u = moqtrun_up_of_key(hub, k);
  return u && u->wt != p->wt && moqtrun_up_pub_open(hub, u);
}

/* Worth waiting for: a non-zero timeout (0 MUST get DOES_NOT_EXIST now
 * unless a publisher announced the namespace -- 18/19 9.5, 22 7.6: the
 * SUBSCRIBE then goes upstream, answered once that one is), or an
 * upstream SUBSCRIBE for k already pending to ride on. */
static int moqtrun_rdv_wanted(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* p,
    const moqctl_subscribe*   m,
    moqtrun_key               k) {
  return moqtrun_rdv_rt(m) || moqtrun_up_announcer(hub, p->wt, k) != 0 ||
         moqtrun_up_rideable(hub, p, k);
}

/* 1 iff a SUBSCRIBE with no publisher is held, not refused at once: worth
 * waiting for (moqtrun_rdv_wanted), a request stream to answer on later
 * (the single-bidi control stream's REQUEST_ERROR names no stream --
 * 10.2.6 lets a relay use a shorter timeout, here none), and a Full Track
 * Name a PUBLISH could ever claim. */
int moqtrun_rdv_holdable(
    wired_moqt_hub*           hub,
    const wired_moqtrun_peer* p,
    const moqctl_subscribe*   m,
    moqtrun_key               k) {
  return p->req && !moqtrun_key_oversized(k) &&
         moqtrun_rdv_wanted(hub, p, m, k);
}

wired_moqtrun_rdv* moqtrun_rdv_free_slot(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++)
    if (!hub->rdv[i].in_use) return &hub->rdv[i];
  return 0;
}
