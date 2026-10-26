#include "app/moqt/run/moqtrun_impl.h"

/* Dedup of a merged subscription (draft-18 9.3 "should deduplicate"),
 * moqtrun_mpub.c's other half. The unit is what the hub forwards whole:
 * a Subgroup stream by (Group, Subgroup) -- one subgroup is one stream,
 * so a second publisher's copy cannot be spliced into the first's -- and
 * a datagram by (Group, Object). The first mirror to forward a Location
 * owns it (MoqtMultiPub.tla claim); a sibling's copy is dropped for that
 * subscriber.
 * shortcut: a Subgroup the first publisher left unfinished is not
 * completed from the sibling's already-dropped copy (no buffering); the
 * sibling's later copies are taken (moqtrun_dd_release). */

static wired_moqtrun_dd moqtrun_dd_key(
    const wired_moqtrun_sub* s, u8 kind, u64 group, u64 id);
static int moqtrun_dd_eq(const wired_moqtrun_dd* a, const wired_moqtrun_dd* b);
static wired_moqtrun_dd* moqtrun_dd_find(
    wired_moqt_hub* hub, const wired_moqtrun_dd* k);
static int  moqtrun_dd_claim(wired_moqt_hub* hub, const wired_moqtrun_dd* k);
static void moqtrun_dd_release_one(
    wired_moqt_hub*            hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* r);
static void moqtrun_mirror_update_track(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      p,
    wired_moqtrun_track*     t,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params);
static void moqtrun_mirror_update_peer(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      p,
    wired_moqtrun_peer*      q,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params);

static wired_moqtrun_dd moqtrun_dd_key(
    const wired_moqtrun_sub* s, u8 kind, u64 group, u64 id) {
  wired_moqtrun_dd k;
  k.owner       = s;
  k.request_id  = s->request_id;
  k.group       = group;
  k.id          = id;
  k.session_idx = (u16)s->session_idx;
  k.kind        = kind;
  k.in_use      = 1;
  return k;
}

/* Same subscription and Location (owner aside). */
static int moqtrun_dd_eq(const wired_moqtrun_dd* a, const wired_moqtrun_dd* b) {
  u64 diff = (u64)(a->in_use ^ b->in_use) |
             (u64)(a->session_idx ^ b->session_idx) | (u64)(a->kind ^ b->kind) |
             (a->request_id ^ b->request_id) | (a->group ^ b->group) |
             (a->id ^ b->id);
  return diff == 0;
}

static wired_moqtrun_dd* moqtrun_dd_find(
    wired_moqt_hub* hub, const wired_moqtrun_dd* k) {
  for (usz i = 0; i < WIRED_MOQTRUN_DD_MAX; i++) {
    if (moqtrun_dd_eq(&hub->dd[i], k)) {
      return &hub->dd[i];
    }
  }
  return 0;
}

/* 1 iff another mirror owns k; else k is (or stays) its owner's. */
static int moqtrun_dd_claim(wired_moqt_hub* hub, const wired_moqtrun_dd* k) {
  wired_moqtrun_dd* d = moqtrun_dd_find(hub, k);
  if (d) {
    return d->owner != k->owner;
  }
  hub->dd[hub->dd_at] = *k;
  hub->dd_at          = (hub->dd_at + 1) % WIRED_MOQTRUN_DD_MAX;
  return 0;
}

/* 1 iff s must not get Location (group, id) of kind (0 stream, 1
 * datagram): a sibling mirror forwarded it. Only a mirrored subscription
 * is looked up. */
int moqtrun_dd_dup(
    wired_moqt_hub*          hub,
    const wired_moqtrun_sub* s,
    u8                       kind,
    u64                      group,
    u64                      id) {
  wired_moqtrun_dd k = moqtrun_dd_key(s, kind, group, id);
  return s->mirrored ? moqtrun_dd_claim(hub, &k) : 0;
}

static void moqtrun_dd_release_one(
    wired_moqt_hub*            hub,
    const wired_moqtrun_sub*   s,
    const wired_moqtrun_relay* r) {
  wired_moqtrun_dd  k = moqtrun_dd_key(s, 0, r->group_id, r->subgroup_id);
  wired_moqtrun_dd* d = moqtrun_dd_find(hub, &k);
  if (d && d->owner == s) {
    d->in_use = 0;
  }
}

/* Slot si of t stops while its relay streams are still open: those
 * Subgroups were never finished for the subscriber, so their claims go
 * (MoqtMultiPub.tla Leave releases only unfinished ones -- a finished
 * one keeps blocking the sibling's duplicate). */
void moqtrun_dd_release(wired_moqt_hub* hub, wired_moqtrun_track* t, usz si) {
  for (usz r = 0; r < WIRED_MOQTRUN_MAX_RELAYS; r++) {
    if (moqtrun_relay_feeds(&t->relays[r], si)) {
      moqtrun_dd_release_one(hub, &t->subs[si], &t->relays[r]);
    }
  }
}

/* Relay r has a stream open toward sub slot si. */
int moqtrun_relay_feeds(const wired_moqtrun_relay* r, usz si) {
  return r->in_use && r->sub_stream_set[si];
}

static void moqtrun_mirror_update_track(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      p,
    wired_moqtrun_track*     t,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params) {
  wired_moqtrun_sub* m =
      moqtrun_live_track_sub_by_rid(t, s->session_idx, s->request_id);
  if (!m || m == s) {
    return;
  }
  (void)moqtrun_upd_apply(hub, p, m, t, params);
  moqtrun_upd_resched(hub, p, m, t);
  moqtrun_ngr_relay(hub, t, params);
  moqtrun_pub_resume(hub, t);
}

static void moqtrun_mirror_update_peer(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      p,
    wired_moqtrun_peer*      q,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    moqtrun_mirror_update_track(hub, p, &q->tracks[i], s, params);
  }
}

/* A REQUEST_UPDATE applied to s reaches its mirrors too: one subscription
 * (draft-22 9.11) whatever the number of publishers feeding it. */
void moqtrun_mirror_update(
    wired_moqt_hub*          hub,
    wired_moqtrun_peer*      p,
    const wired_moqtrun_sub* s,
    const moqctl_params*     params) {
  if (!s->mirrored) {
    return;
  }
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    moqtrun_mirror_update_peer(hub, p, &hub->peers[i], s, params);
  }
}
