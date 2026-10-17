#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_dispatch_req_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin);
static int moqtrun_bidi_is_setup(wired_span data);
static int moqtrun_bidi_adopt(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
static int moqtrun_bidi_ctl(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin);
static int moqtrun_pubst_track_is(const wired_moqtrun_track* t, u64 tag);

static void moqtrun_dispatch_req_stream(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  wired_moqtrun_req* q = moqtrun_req_for(hub, p->wt, stream_id, data);
  if (!q) {
    return;
  }
  p->req = q;
  moqtrun_dispatch_ctl_stream(hub, p, (usz)(p - hub->peers), data);
  moqtrun_req_check_open(hub, p);
  p->req = 0;
  moqtrun_req_note_fin(hub, p, q, fin);
  moqtrun_reqs_tick(hub);
}

/* draft-19 3.3 leniency: a fresh client bidi whose first varint is
 * SETUP's Type is the client control stream, not a request stream. */
static int moqtrun_bidi_is_setup(wired_span data) {
  usz at = 0;
  u64 t  = 0;
  return moqvi_take(data, &at, &t) && t == MOQCTL_T_SETUP;
}

static int moqtrun_bidi_adopt(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (!moqtrun_bidi_is_setup(data)) {
    return 0;
  }
  moqtrun_ctl_adopt_rx(hub, p, sid, data, fin);
  return 1;
}

/* A fresh client bidi's first delivery: kept while it ends inside its
 * first varint (moqtrun_pre_stash), adopted when that varint is SETUP's
 * Type. 1 when consumed; 0 for an existing request stream or any other
 * Type. */
static int moqtrun_bidi_ctl(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 sid,
    wired_span          data,
    int                 fin) {
  if (moqtrun_req_find(hub, p->wt, sid)) {
    return 0;
  }
  return moqtrun_pre_stash(p, sid, data, fin) ||
         moqtrun_bidi_adopt(hub, p, sid, data, fin);
}

/* The control/hold/request decision for a FRESH bidi delivery. */
void moqtrun_dispatch_bidi_fresh(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* p,
    u64                 stream_id,
    wired_span          data,
    int                 fin) {
  if (moqtrun_bidi_ctl(hub, p, stream_id, data, fin)) {
    return;
  }
  if (moqtrun_hold_gate(p)) {
    moqtrun_hold_push(hub, p, stream_id, data, fin);
    return;
  }
  moqtrun_dispatch_req_stream(hub, p, stream_id, data, fin);
}

static int moqtrun_pubst_track_is(const wired_moqtrun_track* t, u64 tag) {
  return t->in_use && t->cache_tag == tag;
}

/* The live incarnation of the track whose cache_tag is tag, else 0. */
wired_moqtrun_track* moqtrun_pubst_track(wired_moqt_hub* hub, u64 tag) {
  usz per = WIRED_MOQTRUN_MAX_TRACKS_PER_PEER;
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS * per; i++) {
    wired_moqtrun_track* t = &hub->peers[i / per].tracks[i % per];
    if (moqtrun_pubst_track_is(t, tag)) {
      return t;
    }
  }
  return 0;
}

/* Opens s as p's subscription to t under the PUBLISH q named (alias and
 * Request ID): its initial parameters are the PUBLISH's (d19 10.19.1
 * "copied over as the default Subscription parameters", d22 3.6.2 "initial
 * Subscription parameters"), plus the SUBSCRIBE_TRACKS's object Range
 * Filters the PUBLISH cannot carry (12-26, d22 3.6.1/9.8), then any the
 * PUBLISH_OK carries (d18/d19 10.2.x admit FORWARD, priority, filters
 * there), applied as an update. */
void moqtrun_pubst_open_sub(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_req*   q,
    wired_moqtrun_track* t,
    wired_moqtrun_sub*   s,
    wired_span           body) {
  moqctl_subscribe  m   = {0};
  moqctl_request_ok ok  = {0};
  usz               off = 0;
  m.request_id          = q->request_id;
  m.params              = moqtrun_subtracks_publish_params(q);
  moqtrun_sub_open(s, t, (usz)(p - hub->peers), q->pub_alias, &m);
  s->rngf_n = q->rngf_n;
  bytes_memcpy(s->rngf, q->rngf, sizeof s->rngf);
  if (moqctl_request_ok_take(p->ver, body, &off, &ok) == MOQCTL_OK) {
    moqtrun_upd_params(s, t, &ok.params);
  }
}
