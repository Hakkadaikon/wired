#include "app/moqt/run/moqtrun_impl.h"

/* Upstream SUBSCRIBE to every matching publisher (hub->multi_publisher;
 * draft-22 7.6 "Relays MUST send SUBSCRIBE messages to all matching
 * publishers. This includes matching both Established subscriptions on
 * the Full Track Name and Namespace Prefix Matching against published
 * Namespaces"; draft-18 9.5). Each announcer covering a wanted Track gets
 * its own upstream entry -- keyed (Full Track Name, publisher session) --
 * unless it already holds the Track (its PUBLISH, an earlier SUBSCRIBE_OK)
 * or refused it (wired_moqtrun_up.failed). A Track is wanted by a waiting
 * SUBSCRIBE and by an Established subscription alike, so an announcer
 * that comes later is asked too. Every SUBSCRIBE_OK claims a track on its
 * publisher and the subscriptions mirror onto it (moqtrun_mpub.c). */

static int moqtrun_up_live_is(const wired_moqtrun_up* u, moqtrun_key k);
static int moqtrun_up_asked(
    wired_moqt_hub* hub, wired_wt_session* wt, moqtrun_key k);
static int moqtrun_up_fan_one(
    wired_moqt_hub*          hub,
    const wired_moqtrun_req* a,
    const wired_wt_session*  s,
    moqtrun_key              k,
    u64                      skip);
static int moqtrun_up_fan_key(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k, u64 skip);
static u64  moqtrun_sub_sess_bit(const wired_moqtrun_sub* s);
static u64  moqtrun_track_sub_bits(const wired_moqtrun_track* t);
static void moqtrun_up_fan_track(wired_moqt_hub* hub, wired_moqtrun_track* t);
static void moqtrun_up_fan_peer(wired_moqt_hub* hub, wired_moqtrun_peer* q);
static int  moqtrun_track_has_sub(const wired_moqtrun_track* t);

static int moqtrun_up_live_is(const wired_moqtrun_up* u, moqtrun_key k) {
  return !u->failed && moqtrun_up_matches(u, k);
}

/* 1 iff an upstream entry for k that the publisher has not refused is
 * open: pending or Established. */
int moqtrun_up_live_of_key(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_live_is(&hub->ups[i], k)) {
      return 1;
    }
  }
  return 0;
}

/* wt was asked for k already, or holds it itself. */
static int moqtrun_up_asked(
    wired_moqt_hub* hub, wired_wt_session* wt, moqtrun_key k) {
  return moqtrun_up_of_key_wt(hub, k, wt) != 0 ||
         moqtrun_peer_track_for_name(moqtrun_find_by_wt(hub, wt), k) != 0;
}

/* 1 when a could serve k but no SUBSCRIBE would open toward it. */
static int moqtrun_up_fan_one(
    wired_moqt_hub*          hub,
    const wired_moqtrun_req* a,
    const wired_wt_session*  s,
    moqtrun_key              k,
    u64                      skip) {
  if (!moqtrun_up_candidate(hub, a, s, k, skip) ||
      moqtrun_up_asked(hub, a->wt, k)) {
    return 0;
  }
  return !moqtrun_up_open(hub, a, k);
}

static int moqtrun_up_fan_key(
    wired_moqt_hub* hub, const wired_wt_session* s, moqtrun_key k, u64 skip) {
  int refused = 0;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    refused |= moqtrun_up_fan_one(hub, &hub->reqs[i], s, k, skip);
  }
  return refused;
}

/* Waiter r asks every announcer of its track; with none left open
 * (all refused, or none at all) it is answered as moqtrun_up_wait_one
 * would. */
void moqtrun_up_fan(wired_moqt_hub* hub, wired_moqtrun_rdv* r) {
  moqtrun_key k = moqtrun_up_rdv_key(r);
  int         refused;
  if (!r->in_use) {
    return;
  }
  refused = moqtrun_up_fan_key(hub, r->wt, k, moqtrun_up_skip(hub, k));
  if (!moqtrun_up_live_of_key(hub, k)) {
    moqtrun_up_unserved(hub, r, refused);
  }
}

/* The sessions holding a subscription on t: as for a waiter, a session's
 * own announcement does not serve its own subscription. */
static u64 moqtrun_track_sub_bits(const wired_moqtrun_track* t) {
  u64 m = 0;
  for (usz si = 0; si < WIRED_MOQTRUN_MAX_SUBS; si++) {
    m |= moqtrun_sub_sess_bit(&t->subs[si]);
  }
  return m;
}

/* An inactive slot's session_idx is unset: never shift by it. */
static u64 moqtrun_sub_sess_bit(const wired_moqtrun_sub* s) {
  return s->active ? (u64)1 << s->session_idx : 0;
}

static int moqtrun_track_has_sub(const wired_moqtrun_track* t) {
  return t && t->in_use && moqtrun_track_sub_bits(t) != 0;
}

static void moqtrun_up_fan_track(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  moqtrun_key k;
  if (!moqtrun_track_has_sub(t)) {
    return;
  }
  k = moqtrun_track_key(t);
  (void)moqtrun_up_fan_key(
      hub, 0, k, moqtrun_up_skip(hub, k) | moqtrun_track_sub_bits(t));
}

static void moqtrun_up_fan_peer(wired_moqt_hub* hub, wired_moqtrun_peer* q) {
  if (!q->in_use) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    moqtrun_up_fan_track(hub, &q->tracks[i]);
  }
}

/* Every Established subscription's track asks the announcers not asked
 * yet (moqtrun_up_sync). */
void moqtrun_up_fan_subs(wired_moqt_hub* hub) {
  if (!hub->multi_publisher) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    moqtrun_up_fan_peer(hub, &hub->peers[i]);
  }
}

/* 1 iff a subscription on some track of k is active: a pending or
 * refused upstream for k is still wanted (moqtrun_up_settle). */
int moqtrun_up_key_subs(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_track* t = moqtrun_peer_track_for_name(&hub->peers[i], k);
    if (moqtrun_track_has_sub(t)) {
      return 1;
    }
  }
  return 0;
}

/* u's request ended without serving (code; the caller did the io). Its
 * waiters are refused once no other publisher of the Track is still open;
 * under multi_publisher u stays as a refusal record so its publisher is
 * not asked again (freed by moqtrun_up_settle once unwanted). */
void moqtrun_up_refused(wired_moqt_hub* hub, wired_moqtrun_up* u, u64 code) {
  moqtrun_key k = moqtrun_up_key(u);
  u->failed     = 1;
  u->track_tag  = 0;
  u->in_use     = hub->multi_publisher;
  if (!moqtrun_up_live_of_key(hub, k)) {
    moqtrun_up_refuse_waiters(hub, k, code);
  }
}

/* The publisher refused u (REQUEST_ERROR, or a FIN with no answer): the
 * hub ends its side too. */
void moqtrun_up_failed(wired_moqt_hub* hub, wired_moqtrun_up* u, u64 code) {
  hub->io.stream_fin(u->wt, u->stream_id);
  moqtrun_up_refused(hub, u, code);
}
