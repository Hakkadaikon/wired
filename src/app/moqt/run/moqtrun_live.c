#include "app/moqt/run/moqtrun_impl.h"

static wired_moqtrun_sub* moqtrun_peer_sub_by_rid(
    wired_moqtrun_peer* q, usz idx, u64 rid, wired_moqtrun_track** t);
static wired_moqtrun_sub* moqtrun_live_peer_sub_by_rid(
    wired_moqtrun_peer* q, usz idx, u64 rid, wired_moqtrun_track** t);
static u64  moqtrun_join_group(const moqfetch_req* m, moqctl_loc jl);
static int  moqtrun_join_bad(const wired_moqtrun_sub* s, u64 group);
static void moqtrun_fetch_joining(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    const moqfetch_req* m);

/* t's subscription for (idx, rid) while t is published, else 0. */
wired_moqtrun_sub* moqtrun_live_track_sub_by_rid(
    wired_moqtrun_track* t, usz idx, u64 rid) {
  return t->in_use ? moqtrun_track_sub_by_rid(t, idx, rid) : 0;
}

static wired_moqtrun_sub* moqtrun_peer_sub_by_rid(
    wired_moqtrun_peer* q, usz idx, u64 rid, wired_moqtrun_track** t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_TRACKS_PER_PEER; i++) {
    *t                   = &q->tracks[i];
    wired_moqtrun_sub* s = moqtrun_live_track_sub_by_rid(*t, idx, rid);
    if (s) {
      return s;
    }
  }
  return 0;
}

static wired_moqtrun_sub* moqtrun_live_peer_sub_by_rid(
    wired_moqtrun_peer* q, usz idx, u64 rid, wired_moqtrun_track** t) {
  return q->in_use ? moqtrun_peer_sub_by_rid(q, idx, rid, t) : 0;
}

/* Peer idx's subscription with Request ID rid on a peer track (*t).
 * Peer tracks only: the hub's own blob and live tracks are never cached,
 * so they are no Joining Fetch target (nor a Standalone one --
 * moqtrun_find_published_track also looks at peer tracks only). */
wired_moqtrun_sub* moqtrun_sub_by_rid(
    wired_moqt_hub* hub, usz idx, u64 rid, wired_moqtrun_track** t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    wired_moqtrun_sub* s =
        moqtrun_live_peer_sub_by_rid(&hub->peers[i], idx, rid, t);
    if (s) {
      return s;
    }
  }
  return 0;
}

/* 10.12.2.1 Start group: Joining Location.Group - Joining Start (never
 * below 0) for a Relative, Joining Start itself for an Absolute Joining
 * Fetch. */
static u64 moqtrun_join_group(const moqfetch_req* m, moqctl_loc jl) {
  if (m->fetch_type == MOQFETCH_ABSOLUTE_JOINING) {
    return m->joining_start;
  }
  return jl.group - u64_min(m->joining_start, jl.group);
}

/* 10.12.2 INVALID_RANGE: no Joining Location (nothing was published at
 * SUBSCRIBE_OK), Forward State 0, or a Start past the Joining Location. */
static int moqtrun_join_bad(const wired_moqtrun_sub* s, u64 group) {
  return !s->has_jl || s->forward_off || group > s->jl.group;
}

/* 10.12.2 Joining Fetch: ends at the subscription's Joining Location so
 * FETCH and SUBSCRIBE meet with no gap or overlap. */
static void moqtrun_fetch_joining(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    const moqfetch_req* m) {
  wired_moqtrun_track* t = 0;
  wired_moqtrun_sub*   s =
      moqtrun_sub_by_rid(hub, peer_idx, m->joining_request_id, &t);
  moqtrun_frange r;
  if (!s) {
    moqtrun_send_request_error(p, MOQFETCH_ERR_INVALID_JOINING_REQUEST_ID);
    return;
  }
  u64 group = moqtrun_join_group(m, s->jl);
  if (moqtrun_join_bad(s, group)) {
    moqtrun_send_request_error(p, MOQCTL_ERR_INVALID_RANGE);
    return;
  }
  r.tag    = t->cache_tag;
  r.props  = moqtrun_track_props(t);
  r.start  = moqctl_loc_of(group, 0);
  r.end    = moqtrun_after(s->jl);
  r.ok_end = s->jl;
  r.rngf   = 0; /* ponytail: a Joining Fetch's own filters are not applied */
  r.rngf_n = 0;
  moqtrun_fetch_start(
      hub,
      moqtrun_fetch_accept(
          hub, p, m->request_id, &r, moqtrun_fetch_order_desc(&m->params)));
}

/* The FETCH body in p's draft: draft-22's (SS9.11) or the draft-18/19
 * one (10.12), both into moqfetch_req. */
int moqtrun_fetch_take(
    const wired_moqtrun_peer* p, wired_span body, moqfetch_req* m) {
  if (moqver_caps(p->ver) & MOQVER_CAP_FETCH_BODY_V22) {
    return moqfetch_req22_take(body, m);
  }
  return moqfetch_req19_take(p->ver, body, m);
}

/* The decoded FETCH m routed by kind. draft-22 dropped the Joining Fetch
 * (SS9.11 names one Fetch shape only), so a session on the draft-22 body
 * presenting the Joining structure closes with PROTOCOL_VIOLATION. */
void moqtrun_fetch_route(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    usz                 peer_idx,
    const moqfetch_req* m) {
  if (!m->is_joining) {
    moqtrun_fetch_standalone(hub, p, m);
    return;
  }
  if (moqver_caps(p->ver) & MOQVER_CAP_FETCH_BODY_V22) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  moqtrun_fetch_joining(hub, p, peer_idx, m);
}
