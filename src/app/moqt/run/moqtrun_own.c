#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_sub_holds_alias(const wired_moqtrun_sub* s, usz pi, u64 a);
static int moqtrun_subs_hold_alias(const wired_moqtrun_track* x, usz pi, u64 a);
static int moqtrun_track_alias_clash(
    const wired_moqtrun_track* x, const wired_moqtrun_track* t, usz pi, u64 a);
static int moqtrun_peer_tracks_clash(
    const wired_moqtrun_peer* q, const wired_moqtrun_track* t, usz pi, u64 a);
static int moqtrun_peer_clash(
    const wired_moqtrun_peer* q, const wired_moqtrun_track* t, usz pi, u64 a);
static int moqtrun_own_alias_clash(
    const wired_moqtrun_track* x, const wired_moqtrun_track* t, u64 a);

/* draft SS10.9 PUBLISH: decode, then authorize and claim
 * (moqtrun_publish_checked). */
void moqtrun_handle_publish(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  usz            off = 0;
  moqctl_publish m;
  if (!moqtrun_take_tok_or_close(
          hub, p, moqctl_publish_take(p->ver, body, &off, &m), &m.params))
    return;
  moqtrun_publish_checked(hub, p, peer_idx, &m);
}

/* p's matching track slot if p is a connected peer, else 0 -- guards the
 * in_use check ahead of the name scan so the caller's loop body is one
 * unconditional call. */
wired_moqtrun_track* moqtrun_peer_track_for_name(
    wired_moqtrun_peer* p, moqtrun_key k) {
  return p->in_use ? moqtrun_track_slot_for_name(p, k) : 0;
}

/* Finds the track whose PUBLISHed Full Track Name (namespace AND name,
 * draft 1.5) equals the SUBSCRIBE's, across every connected peer. */
wired_moqtrun_track* moqtrun_find_published_track(
    wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_track* t = moqtrun_peer_track_for_name(&hub->peers[i], k);
    if (t) return t;
  }
  return 0;
}

wired_moqtrun_sub* moqtrun_sub_slot(wired_moqtrun_track* track) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++)
    if (!track->subs[i].active) return &track->subs[i];
  return 0;
}

/* --- Track Alias per subscriber session (draft-22 3.1.3, draft-19 11.1):
 * on each subscriber's session the HUB is the publisher, so it picks the
 * alias SUBSCRIBE_OK / its own PUBLISH names, and two Tracks MUST NOT
 * share one within that session -- yet every publisher picks its own,
 * so two publishers' tracks can carry the same number. The hub prefers
 * the publisher's own alias (relayed bytes then pass verbatim), else the
 * lowest free one, and re-spells each relayed SUBGROUP_HEADER /
 * OBJECT_DATAGRAM to its destination's alias (moqtrun_alias_splice). --- */

/* 1 iff s is session pi's Established subscription under alias a. */
static int moqtrun_sub_holds_alias(const wired_moqtrun_sub* s, usz pi, u64 a) {
  return s->active && s->session_idx == pi && s->track_alias == a;
}

static int moqtrun_subs_hold_alias(
    const wired_moqtrun_track* x, usz pi, u64 a) {
  for (usz s = 0; s < WIRED_MOQTRUN_MAX_SUBS; s++)
    if (moqtrun_sub_holds_alias(&x->subs[s], pi, a)) return 1;
  return 0;
}

/* 1 iff x, a live track other than t, gives session pi alias a. */
static int moqtrun_track_alias_clash(
    const wired_moqtrun_track* x, const wired_moqtrun_track* t, usz pi, u64 a) {
  return x != t && x->in_use && moqtrun_subs_hold_alias(x, pi, a);
}

static int moqtrun_peer_tracks_clash(
    const wired_moqtrun_peer* q, const wired_moqtrun_track* t, usz pi, u64 a) {
  for (usz k = 0; k < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; k++)
    if (moqtrun_track_alias_clash(&q->tracks[k], t, pi, a)) return 1;
  return 0;
}

static int moqtrun_peer_clash(
    const wired_moqtrun_peer* q, const wired_moqtrun_track* t, usz pi, u64 a) {
  return q->in_use && moqtrun_peer_tracks_clash(q, t, pi, a);
}

int moqtrun_peers_clash(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, usz pi, u64 a) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++)
    if (moqtrun_peer_clash(&hub->peers[i], t, pi, a)) return 1;
  return 0;
}

/* The hub's own blob/live track x: its framed bytes always carry
 * own_alias, so that alias is reserved in every session. */
static int moqtrun_own_alias_clash(
    const wired_moqtrun_track* x, const wired_moqtrun_track* t, u64 a) {
  return x != t && x->in_use && x->own_alias == a;
}

int moqtrun_own_clash(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t, u64 a) {
  return moqtrun_own_alias_clash(&hub->blob_track, t, a) ||
         moqtrun_own_alias_clash(&hub->live.track, t, a);
}

moqtrun_key moqtrun_track_key(const wired_moqtrun_track* t) {
  moqtrun_key k;
  k.ns   = wired_span_of(t->ns, t->ns_len);
  k.name = wired_span_of(t->name, t->name_len);
  return k;
}
