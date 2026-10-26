#include "app/moqt/run/moqtrun_impl.h"

/* ====== several publishers of one Track (draft-18 9.3, draft-22 7.6) ======
 * With hub->multi_publisher on, one Full Track Name may be held by tracks
 * on several publisher peers (PUBLISHes and upstream SUBSCRIBE_OKs, one per
 * publisher). A downstream subscription is recorded on every one of them:
 * "mirrors" sharing the subscriber's session_idx, Request ID and Track
 * Alias (moqtrun_reattach_one_sub copies the state its SUBSCRIBE left), so
 * each publisher's Objects fan out through the unchanged relay paths, and
 * hub->dd drops a Location a sibling mirror already forwarded. A mirror
 * whose publisher ends folds into a surviving one with no message; the
 * last one ends with the subscription's PUBLISH_DONE. Model:
 * tasks/loopeng/MoqtMultiPub (NoDup, NoStaleClaim, Complete). */

static int moqtrun_mirror_is(
    const wired_moqtrun_sub* m, const wired_moqtrun_sub* s);
static wired_moqtrun_sub* moqtrun_track_mirror(
    wired_moqtrun_track* t, const wired_moqtrun_sub* s);
static wired_moqtrun_sub* moqtrun_live_track_mirror(
    wired_moqtrun_track* t, const wired_moqtrun_sub* s);
static wired_moqtrun_sub* moqtrun_peer_mirror(
    wired_moqtrun_peer* q, const wired_moqtrun_sub* s);
static wired_moqtrun_sub* moqtrun_live_peer_mirror(
    wired_moqtrun_peer* q, const wired_moqtrun_sub* s);
static wired_moqtrun_sub* moqtrun_hub_mirror(
    wired_moqt_hub* hub, const wired_moqtrun_sub* s);
static void moqtrun_mirror_peer(wired_moqt_hub* hub, usz i, moqtrun_key k);

/* m is another slot of s's subscription. */
static int moqtrun_mirror_is(
    const wired_moqtrun_sub* m, const wired_moqtrun_sub* s) {
  return m != s && moqtrun_sub_is_req(m, s->session_idx, s->request_id);
}

static wired_moqtrun_sub* moqtrun_track_mirror(
    wired_moqtrun_track* t, const wired_moqtrun_sub* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_mirror_is(&t->subs[i], s)) {
      return &t->subs[i];
    }
  }
  return 0;
}

static wired_moqtrun_sub* moqtrun_live_track_mirror(
    wired_moqtrun_track* t, const wired_moqtrun_sub* s) {
  return t->in_use ? moqtrun_track_mirror(t, s) : 0;
}

static wired_moqtrun_sub* moqtrun_peer_mirror(
    wired_moqtrun_peer* q, const wired_moqtrun_sub* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    wired_moqtrun_sub* m = moqtrun_live_track_mirror(&q->tracks[i], s);
    if (m) {
      return m;
    }
  }
  return 0;
}

static wired_moqtrun_sub* moqtrun_live_peer_mirror(
    wired_moqtrun_peer* q, const wired_moqtrun_sub* s) {
  return q->in_use ? moqtrun_peer_mirror(q, s) : 0;
}

static wired_moqtrun_sub* moqtrun_hub_mirror(
    wired_moqt_hub* hub, const wired_moqtrun_sub* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_sub* m = moqtrun_live_peer_mirror(&hub->peers[i], s);
    if (m) {
      return m;
    }
  }
  return 0;
}

/* Another publisher's slot of s's subscription, else 0. */
wired_moqtrun_sub* moqtrun_mirror_of(
    wired_moqt_hub* hub, const wired_moqtrun_sub* s) {
  return hub->multi_publisher ? moqtrun_hub_mirror(hub, s) : 0;
}

/* slot just (re)attached: with a sibling, both dedup from now on. */
void moqtrun_mirror_mark(wired_moqt_hub* hub, wired_moqtrun_sub* slot) {
  wired_moqtrun_sub* m = moqtrun_mirror_of(hub, slot);
  if (m) {
    m->mirrored    = 1;
    slot->mirrored = 1;
  }
}

static void moqtrun_mirror_peer(wired_moqt_hub* hub, usz i, moqtrun_key k) {
  wired_moqtrun_track* t = moqtrun_peer_track_for_name(&hub->peers[i], k);
  if (t) {
    moqtrun_reattach_subs(hub, t, i, k);
  }
}

/* A SUBSCRIBE just Established on one track of k: every other publisher's
 * track of k carries it too (draft-22 7.6 all matching publishers). */
void moqtrun_mirror_all(wired_moqt_hub* hub, moqtrun_key k) {
  if (!hub->multi_publisher) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    moqtrun_mirror_peer(hub, i, k);
  }
}

/* Slot si of t ends but a sibling still carries the subscription: si
 * stops with no message (its open streams reset), its unfinished claims
 * are released for the sibling to send (MoqtMultiPub.tla Leave), and its
 * Stream Count moves to the sibling's final PUBLISH_DONE (draft-22 9.9).
 * 0 when there is no sibling: the caller ends it as before. */
int moqtrun_mirror_fold(wired_moqt_hub* hub, wired_moqtrun_track* t, usz si) {
  wired_moqtrun_sub* s = &t->subs[si];
  wired_moqtrun_sub* m = s->active ? moqtrun_mirror_of(hub, s) : 0;
  if (!m) {
    return 0;
  }
  m->stream_count += s->stream_count;
  moqtrun_dd_release(hub, t, si);
  moqtrun_sub_stop(hub, t, s, MOQTRUN_RESET_CANCELLED);
  return 1;
}

/* moqtrun_sub_done_slot for a subscription that may have mirrors: only the
 * last one sends PUBLISH_DONE. */
void moqtrun_mirror_done_slot(
    wired_moqt_hub* hub, wired_moqtrun_track* t, usz si, u64 status) {
  if (!moqtrun_mirror_fold(hub, t, si)) {
    moqtrun_sub_done_slot(hub, t, si, status);
  }
}
