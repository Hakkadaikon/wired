#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_sub_state_clash(
    const wired_moqtrun_peer* p, usz i, const wired_moqtrun_track* t, u64 a);
static int moqtrun_ring_clash(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t, u64 a);
static int moqtrun_req_is_pub_on(
    const wired_moqtrun_req* q, const wired_wt_session* wt);
static int moqtrun_req_alias_clash(
    const wired_moqtrun_req*   q,
    const wired_wt_session*    wt,
    const wired_moqtrun_track* t,
    u64                        a);
static int moqtrun_reqs_clash(
    const wired_moqt_hub*      hub,
    const wired_wt_session*    wt,
    const wired_moqtrun_track* t,
    u64                        a);
static int moqtrun_alias_live(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a);
static int moqtrun_alias_kept(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a);
static int moqtrun_alias_taken(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a);
static int moqtrun_reattach_peer_live(
    const wired_moqt_hub* hub, usz i, usz pub_idx);

/* Ring entry i of p: a subscription to another Track than t under alias
 * a, which p's client may still believe Established (a REPUBLISH
 * re-attaches it under that alias, moqtrun_reattach_one_sub). A
 * forgotten (cancelled) entry's name is over-long and never counts. */
static int moqtrun_sub_state_clash(
    const wired_moqtrun_peer* p, usz i, const wired_moqtrun_track* t, u64 a) {
  return p->sub_state[i].track_alias == a &&
         p->sub_name_lens[i] <= WIRED_MOQTRUN_MAX_NAME &&
         !moqtrun_sub_name_eq(p, i, moqtrun_track_key(t));
}

static int moqtrun_ring_clash(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t, u64 a) {
  for (usz i = 0; i < p->sub_names_n; i++) {
    if (moqtrun_sub_state_clash(p, i, t, a)) {
      return 1;
    }
  }
  return 0;
}

/* 1 iff q is a PUBLISH this hub opened on session wt. */
static int moqtrun_req_is_pub_on(
    const wired_moqtrun_req* q, const wired_wt_session* wt) {
  return q->in_use && q->pub_origin_rid && q->wt == wt;
}

static int moqtrun_req_alias_clash(
    const wired_moqtrun_req*   q,
    const wired_wt_session*    wt,
    const wired_moqtrun_track* t,
    u64                        a) {
  return moqtrun_req_is_pub_on(q, wt) && q->pub_track_tag != t->cache_tag &&
         q->pub_alias == a;
}

static int moqtrun_reqs_clash(
    const wired_moqt_hub*      hub,
    const wired_wt_session*    wt,
    const wired_moqtrun_track* t,
    u64                        a) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_req_alias_clash(&hub->reqs[i], wt, t, a)) {
      return 1;
    }
  }
  return 0;
}

/* Session pi already names another Track than t by a: a subscription,
 * a hub track's reserved alias, a remembered subscription, or a PUBLISH
 * the hub opened there. */
static int moqtrun_alias_live(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a) {
  return moqtrun_peers_clash(hub, t, pi, a) || moqtrun_own_clash(hub, t, a);
}

static int moqtrun_alias_kept(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a) {
  const wired_moqtrun_peer* p = &hub->peers[pi];
  return moqtrun_ring_clash(p, t, a) || moqtrun_reqs_clash(hub, p->wt, t, a);
}

static int moqtrun_alias_taken(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t, u64 a) {
  return moqtrun_alias_live(hub, pi, t, a) || moqtrun_alias_kept(hub, pi, t, a);
}

/* The Track Alias session pi knows t by: t's own (publisher-chosen) alias
 * unless another Track holds it there, else the lowest free one. */
u64 moqtrun_session_alias(
    const wired_moqt_hub* hub, usz pi, const wired_moqtrun_track* t) {
  u64 a = 0;
  if (!moqtrun_alias_taken(hub, pi, t, t->own_alias)) {
    return t->own_alias;
  }
  while (moqtrun_alias_taken(hub, pi, t, a)) {
    a++;
  }
  return a;
}

/* 1 if sub is an Established subscription held by peer index idx. */
int moqtrun_sub_is_peer(const wired_moqtrun_sub* sub, usz idx) {
  return sub->active && sub->session_idx == idx;
}

/* The Established sub slot peer index idx holds on t, else 0. */
wired_moqtrun_sub* moqtrun_track_sub_of_peer(wired_moqtrun_track* t, usz idx) {
  for (usz s = 0; s < WIRED_MOQTRUN_MAX_SUBS; s++) {
    if (moqtrun_sub_is_peer(&t->subs[s], idx)) {
      return &t->subs[s];
    }
  }
  return 0;
}

/* 1 iff peer i is a live peer OTHER than the publisher. */
static int moqtrun_reattach_peer_live(
    const wired_moqt_hub* hub, usz i, usz pub_idx) {
  return i != pub_idx && hub->peers[i].in_use;
}

/* Re-attach eligibility: a live, different peer, not already subscribed on
 * this track, that recorded a SUBSCRIBE for this name. */
int moqtrun_reattach_wanted(
    const wired_moqt_hub* hub,
    wired_moqtrun_track*  t,
    usz                   i,
    usz                   pub_idx,
    moqtrun_key           k) {
  if (!moqtrun_reattach_peer_live(hub, i, pub_idx)) {
    return 0;
  }
  if (moqtrun_track_sub_of_peer(t, i)) {
    return 0;
  }
  return moqtrun_sub_name_known(&hub->peers[i], k);
}
