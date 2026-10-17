#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_subtracks_send_skipped(
    wired_moqtrun_req* st, const wired_moqtrun_track* t);
static int moqtrun_subtracks_opened(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st);
static int moqtrun_subtracks_try_open(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st);
static void moqtrun_subtracks_offer(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  st_peer,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t);
static void moqtrun_subtracks_attempt(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  st_peer,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t,
    usz                  slot);
static void moqtrun_subtracks_sync_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t,
    usz                  pub_idx,
    usz                  slot);
static void moqtrun_subtracks_sync_track(
    wired_moqt_hub* hub, usz pub_idx, usz track_idx);
static void moqtrun_subtracks_sync_peer(wired_moqt_hub* hub, usz pub_idx);

static void moqtrun_subtracks_send_skipped(
    wired_moqtrun_req* st, const wired_moqtrun_track* t) {
  moqns_pub_skipped m;
  u8
      msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS +
          WIRED_MOQTRUN_MAX_NAME];
  usz n;
  moqtrun_subtracks_ns_suffix(st, t, &m.ns);
  m.name = wired_span_of(t->name, t->name_len);
  n      = moqtrun_envelope_put(
      wired_mspan_of(msg, sizeof msg), MOQCTL_T_PUBLISH_SKIPPED,
      moqtrun_subtracks_encode_skip, &m);
  moqtrun_req_queue(st, wired_span_of(msg, n));
}

/* 1 iff q is non-0 and names a successfully opened PUBLISH. */
static int moqtrun_subtracks_opened(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  if (!q) {
    return 0;
  }
  return moqtrun_subtracks_open_pub(hub, st_peer, q, t, st);
}

/* 1 iff q names a successfully opened PUBLISH; releases a claimed-but-
 * unopened slot before reporting failure, so the caller's only remaining
 * branch is "sent or not". */
static int moqtrun_subtracks_try_open(
    wired_moqt_hub*            hub,
    wired_moqtrun_peer*        st_peer,
    wired_moqtrun_req*         q,
    const wired_moqtrun_track* t,
    const wired_moqtrun_req*   st) {
  if (moqtrun_subtracks_opened(hub, st_peer, q, t, st)) {
    return 1;
  }
  if (q) {
    q->in_use = 0;
  }
  return 0;
}

/* One candidate (st, t) pair: PUBLISH if a bidi stream opens, else
 * PUBLISH_SKIPPED (the resource-exhaustion choice settled in design.md
 * section 5) -- and mark the attempt either way (exactly once). */
static void moqtrun_subtracks_offer(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  st_peer,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t) {
  wired_moqtrun_req* q =
      moqtrun_subtracks_claim_slot(hub, st_peer, st->request_id);
  if (!moqtrun_subtracks_try_open(hub, st_peer, q, t, st)) {
    moqtrun_subtracks_send_skipped(st, t);
  }
}

/* A session already subscribed to t (a held SUBSCRIBE that t's PUBLISH
 * resolved, moqtrun_rdv_resolve) is marked tried with nothing sent:
 * 18/19 9.5, 22 7.6 "MUST NOT also forward the PUBLISH to that
 * subscriber". */
static void moqtrun_subtracks_attempt(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  st_peer,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t,
    usz                  slot) {
  if (!moqtrun_track_sub_of_peer(t, (usz)(st_peer - hub->peers))) {
    moqtrun_subtracks_offer(hub, st_peer, st, t);
  }
  moqtrun_subtracks_mark_tried(st, t, slot);
}

/* One (SUBSCRIBE_TRACKS, track) pair at hub->reqs[i]: attempts it when it
 * is both a live SUBSCRIBE_TRACKS and a fresh candidate, else a no-op --
 * split out so the scanning loop above carries no branches of its own. */
static void moqtrun_subtracks_sync_one(
    wired_moqt_hub*      hub,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t,
    usz                  pub_idx,
    usz                  slot) {
  wired_moqtrun_peer* sp;
  usz                 st_idx;
  if (!moqtrun_disc_is(st, MOQCTL_T_SUBSCRIBE_TRACKS)) {
    return;
  }
  sp     = moqtrun_find_by_wt(hub, st->wt);
  st_idx = (usz)(sp - hub->peers);
  if (moqtrun_subtracks_candidate(st, t, pub_idx, st_idx, slot)) {
    moqtrun_subtracks_attempt(hub, sp, st, t, slot);
  }
}

/* Every live SUBSCRIBE_TRACKS against every in-use track of peer pub_idx:
 * a hub-wide O(sessions*tracks*reqs) scan, the same shape as
 * moqtrun_disc_sync's (ponytail: fine at this hub's fixed small
 * capacities). */
static void moqtrun_subtracks_sync_track(
    wired_moqt_hub* hub, usz pub_idx, usz track_idx) {
  wired_moqtrun_track* t    = &hub->peers[pub_idx].tracks[track_idx];
  usz                  slot = moqtrun_subtracks_slot(pub_idx, track_idx);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    moqtrun_subtracks_sync_one(hub, &hub->reqs[i], t, pub_idx, slot);
  }
}

static void moqtrun_subtracks_sync_peer(wired_moqt_hub* hub, usz pub_idx) {
  for (usz ti = 0; ti < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; ti++) {
    moqtrun_subtracks_sync_track(hub, pub_idx, ti);
  }
}

void moqtrun_subtracks_sync(wired_moqt_hub* hub) {
  for (usz pi = 0; pi < WIRED_MOQTRUN_MAX_SESSIONS; pi++) {
    if (hub->peers[pi].in_use) {
      moqtrun_subtracks_sync_peer(hub, pi);
    }
  }
}

/* A track's retirement (unpublish / slot reuse, T-07/T-08): every PUBLISH
 * stream this hub opened for it is reset, dangling-free, the same
 * fill-design pattern moqtrun_fills_upstream_gone uses for fetch fills.
 * Already-answered (q->live, REQUEST_OK) slots are reset too -- the
 * SUBSCRIBE_TRACKS-established subscription cannot outlive the track that
 * no longer exists, unlike a SUBSCRIBE_TRACKS cancel (T-10), which leaves
 * them alone. */
int moqtrun_subtracks_pub_of_tag(const wired_moqtrun_req* q, u64 tag) {
  return q->in_use && q->pub_origin_rid && q->pub_track_tag == tag;
}
