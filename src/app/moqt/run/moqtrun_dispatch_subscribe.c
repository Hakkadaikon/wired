#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_subtracks_tried(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t, usz slot);
static int moqtrun_subtracks_matches(
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t,
    usz                        pub_idx,
    usz                        st_peer_idx);
static void moqtrun_subtracks_u8_add(moqctl_params* out, u64 type, u8 v);

void moqtrun_dispatch_subscribe_tracks(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqns_req m;
  (void)peer_idx;
  if (!p->req) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return;
  }
  if (!moqtrun_take_tok_or_close(
          hub, p, moqns_subscribe_tracks_take(p->ver, body, &m), &m.params))
    return;
  moqtrun_subtracks_admit(hub, p, &m);
}

/* Flat hub-wide track slot index (wired_moqtrun_req.attempted_tag's own
 * doc): stable across a track's whole life in one peer slot, used only to
 * index that fixed-size array, never stored as a pointer/index into the
 * track itself. */
usz moqtrun_subtracks_slot(usz peer_idx, usz track_idx) {
  return peer_idx * WIRED_MOQTRUN_MAX_TRACKS_PER_PEER + track_idx;
}

/* 1 iff st (a live SUBSCRIBE_TRACKS) already tried a PUBLISH or
 * PUBLISH_SKIPPED for this track's CURRENT incarnation (design's cache_tag
 * generation guard: a slot reused by a newer PUBLISH is untried again). */
static int moqtrun_subtracks_tried(
    const wired_moqtrun_req* st, const wired_moqtrun_track* t, usz slot) {
  return st->attempted_tag[slot] == t->cache_tag;
}

void moqtrun_subtracks_mark_tried(
    wired_moqtrun_req* st, const wired_moqtrun_track* t, usz slot) {
  st->attempted_tag[slot] = t->cache_tag;
}

/* 10.19: matches the Track Namespace Prefix (moqtrun_disc_starts, the same
 * byte-prefix-of-fields test SUBSCRIBE_NAMESPACE uses) and excludes tracks
 * published BY the subscriber itself (1753: "excluding tracks published by
 * the subscriber"). */
static int moqtrun_subtracks_matches(
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t,
    usz                        pub_idx,
    usz                        st_peer_idx) {
  u64        n_pre, n_all;
  wired_span pre, all;
  if (pub_idx == st_peer_idx) return 0;
  pre = moqtrun_disc_fields(st, &n_pre);
  all = moqtrun_disc_fields_of(wired_span_of(t->ns, t->ns_len), &n_all);
  return moqtrun_disc_starts(pre, all) && moqtrun_subtracks_tp_pass(st, t);
}

int moqtrun_subtracks_candidate(
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t,
    usz                        pub_idx,
    usz                        st_peer_idx,
    usz                        slot) {
  if (!t->in_use || moqtrun_subtracks_tried(st, t, slot)) return 0;
  return moqtrun_subtracks_matches(st, t, pub_idx, st_peer_idx);
}

/* Appends one uint8 Parameter to out. */
static void moqtrun_subtracks_u8_add(moqctl_params* out, u64 type, u8 v) {
  out->items[out->n].type = type;
  out->items[out->n].enc  = MOQCTL_PENC_UINT8;
  out->items[out->n].u8v  = v;
  out->n++;
}

/* T-12: the Parameters this SUBSCRIBE_TRACKS recorded (moqtrun_subtracks_
 * note_params), reflected into one generated PUBLISH. Of what d22 9.18
 * admits on SUBSCRIBE_TRACKS, 9.8 lets only FORWARD and GROUP_ORDER into a
 * PUBLISH (AUTHORIZATION_TOKEN "MUST NOT be copied", 9.20.2), so these two
 * are the whole "explicitly communicated" set (3.6.2). */
moqctl_params moqtrun_subtracks_publish_params(const wired_moqtrun_req* st) {
  moqctl_params out = {0};
  if (st->has_forward)
    moqtrun_subtracks_u8_add(&out, MOQCTL_PARAM_FORWARD, st->forward);
  if (st->group_order)
    moqtrun_subtracks_u8_add(&out, MOQCTL_PARAM_GROUP_ORDER, st->group_order);
  return out;
}

/* Claims a free hub-wide request slot for a hub-opened PUBLISH, addressed
 * to st_peer's session (the SUBSCRIBE_TRACKS's own receiver per 10.9/1751)
 * and owned by st's request_id (moqtrun.h's pub_origin_rid doc). Never the
 * per-session WIRED_MOQTRUN_MAX_REQS_PER_SESSION cap, which bounds
 * CLIENT-opened request streams only. */
wired_moqtrun_req* moqtrun_subtracks_claim_slot(
    wired_moqt_hub* hub, wired_moqtrun_peer* st_peer, u64 st_rid) {
  wired_moqtrun_req* q = moqtrun_req_free_slot(hub);
  if (!q) return 0;
  moqtrun_req_open(q, st_peer->wt, 0);
  q->pub_origin_rid = st_rid;
  q->request_id     = st_peer->request_id_next;
  st_peer->request_id_next += 2;
  return q;
}
