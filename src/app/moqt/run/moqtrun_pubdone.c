#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_rp_of(
    const wired_moqtrun_rdv* r, const wired_moqtrun_peer* p);
static void moqtrun_track_end_slot(
    wired_moqt_hub*         hub,
    wired_moqtrun_track*    t,
    usz                     si,
    const wired_moqtrun_up* u,
    u64                     status);
static void moqtrun_track_end_or_fold(
    wired_moqt_hub*         hub,
    wired_moqtrun_track*    t,
    usz                     si,
    const wired_moqtrun_up* u,
    u64                     status);
static u64 moqtrun_pubdone_status(const wired_moqtrun_track* t);
static int moqtrun_pubdone_relaying(const wired_moqtrun_track* t);
static int moqtrun_pubdone_caught_up(const wired_moqtrun_track* t);
static int moqtrun_pubdone_armed(const wired_moqtrun_track* t);
static int moqtrun_pubdone_due(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static int moqtrun_track_malformed(const wired_moqtrun_track* t);

static int moqtrun_rp_of(
    const wired_moqtrun_rdv* r, const wired_moqtrun_peer* p) {
  return r->in_use && r->repath && r->wt == p->wt;
}

/* p's GOAWAY drain ran out (moqtrun_drain_flush): each of its waits for
 * a new path ends now with PUBLISH_DONE GOING_AWAY, as its Established
 * subscriptions do. */
void moqtrun_rp_flush(wired_moqt_hub* hub, const wired_moqtrun_peer* p) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rp_of(&hub->rdv[i], p)) {
      hub->rdv[i].done_status = MOQCTL_DONE_GOING_AWAY;
      moqtrun_rdv_answer(hub, &hub->rdv[i], moqtrun_rp_do_done, 0, 0);
    }
  }
}

/* A new path's SUBSCRIBE_OK: a waiter moqtrun_reattach_subs could not
 * re-attach to t (its own session publishes t, or its remembered state was
 * overwritten) ends with its one PUBLISH_DONE. t's subs[] is never full
 * here: t was just claimed (subs cleared), each other session takes at
 * most one slot, and WIRED_MOQTRUN_MAX_SUBS is one less than the
 * sessions. */
void moqtrun_rp_do_relinked(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      sp,
    const wired_moqtrun_rdv* r,
    wired_moqtrun_track*     t,
    u64                      code) {
  usz pi = (usz)(sp - hub->peers);
  if (!moqtrun_track_sub_by_rid(t, pi, sp->req->request_id)) {
    moqtrun_rp_do_done(hub, sp, r, t, code);
  }
}

/* Sub slot si's end: a wait for a new path, or -- status MOQTRUN_RP_NONE,
 * or no room to wait -- PUBLISH_DONE now. */
static void moqtrun_track_end_slot(
    wired_moqt_hub*         hub,
    wired_moqtrun_track*    t,
    usz                     si,
    const wired_moqtrun_up* u,
    u64                     status) {
  if (status == MOQTRUN_RP_NONE) {
    moqtrun_sub_done_slot(hub, t, si, moqtrun_pubdone_status(t));
    return;
  }
  if (!moqtrun_rp_wait(hub, t, si, u, status)) {
    moqtrun_sub_done_slot(hub, t, si, status);
  }
}

/* A slot another publisher's track still carries folds into it
 * (moqtrun_mirror_fold); any other slot ends. */
static void moqtrun_track_end_or_fold(
    wired_moqt_hub*         hub,
    wired_moqtrun_track*    t,
    usz                     si,
    const wired_moqtrun_up* u,
    u64                     status) {
  if (!moqtrun_mirror_fold(hub, t, si)) {
    moqtrun_track_end_slot(hub, t, si, u, status);
  }
}

void moqtrun_track_ended(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  wired_moqtrun_up* u      = moqtrun_up_of_track(hub, t);
  u64               status = u ? moqtrun_rp_status(t) : MOQTRUN_RP_NONE;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    moqtrun_track_end_or_fold(hub, t, si, u, status);
  }
}

/* A publisher's session is ending: every subscription to its tracks ends
 * with TRACK_ENDED (10.11). */
void moqtrun_peer_tracks_ended(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (p->tracks[t].in_use) {
      moqtrun_track_ended(hub, &p->tracks[t]);
    }
  }
}

/* ============ publisher's PUBLISH_DONE relayed (draft 10.11) ============
 * draft-ietf-moq-transport-18/19 10.11, draft-22 9.9. The publisher's
 * PUBLISH_DONE ends its PUBLISH; each subscriber of the track gets its own
 * PUBLISH_DONE: the publisher's Status Code, spelled for the subscriber's
 * draft (moqtrun_done_emit), and as Stream Count the streams the HUB
 * opened toward that subscriber (wired_moqtrun_sub.stream_count) -- the
 * number it can count. The hub is itself a sender bound by "MUST NOT send
 * PUBLISH_DONE until it has closed all streams it will ever open", and
 * the publisher's message may arrive before its late-opening streams, so
 * it waits until the hub saw as many upstream streams as the publisher
 * counted and none is still being relayed; WIRED_MOQTRUN_PUBDONE_WAIT_MS
 * bounds the wait. Then the track is retired and the hub's side of the
 * PUBLISH stream ends (3.3.2). A session close or stream reset meanwhile
 * sends it at once (moqtrun_track_ended, moqtrun_pubdone_flush). */

/* The status a track's subscribers get when it ends now: the publisher's
 * own PUBLISH_DONE status when one is waiting, else TRACK_ENDED. */
static u64 moqtrun_pubdone_status(const wired_moqtrun_track* t) {
  if (t->malformed) {
    return MOQCTL_DONE_MALFORMED_TRACK;
  }
  return t->pubdone_pending ? t->pubdone_status : MOQCTL_DONE_TRACK_ENDED;
}

/* p's track claimed by its PUBLISH of Request ID rid, else 0. */
wired_moqtrun_track* moqtrun_pubdone_track_of(wired_moqtrun_peer* p, u64 rid) {
  for (usz t = 0; t < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; t++) {
    if (moqtrun_track_is_req(&p->tracks[t], rid)) {
      return &p->tracks[t];
    }
  }
  return 0;
}

static int moqtrun_pubdone_relaying(const wired_moqtrun_track* t) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    if (t->relays[r].in_use) {
      return 1;
    }
  }
  return 0;
}

/* Every stream the publisher counted reached the hub and was relayed to
 * its end. */
static int moqtrun_pubdone_caught_up(const wired_moqtrun_track* t) {
  return t->up_streams >= t->pubdone_streams && !moqtrun_pubdone_relaying(t);
}

static int moqtrun_pubdone_armed(const wired_moqtrun_track* t) {
  return t->in_use && t->pubdone_pending;
}

static int moqtrun_pubdone_due(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return moqtrun_pubdone_armed(t) &&
         (moqtrun_pubdone_caught_up(t) ||
          hub->live.last_now_ms >= t->pubdone_deadline);
}

/* A Malformed Track ends at once (draft-22 12.1 "immediately terminate
 * downstream subscriptions"). */
static int moqtrun_track_malformed(const wired_moqtrun_track* t) {
  return t->in_use && t->malformed;
}

int moqtrun_pubdone_ready(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  return moqtrun_track_malformed(t) || moqtrun_pubdone_due(hub, t);
}
