#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_rdv_on_stream(
    const wired_moqtrun_rdv* r, const wired_wt_session* s, u64 stream_id);
static int  moqtrun_rdv_held_here(const wired_moqtrun_peer* p);
static void moqtrun_route_peer_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    wired_span              body);
static int moqtrun_ns_field_eq(wired_span f, const char* z, usz n);

static int moqtrun_rdv_on_stream(
    const wired_moqtrun_rdv* r, const wired_wt_session* s, u64 stream_id) {
  return moqtrun_rdv_owned(r, s) && r->stream_id == stream_id;
}

/* A cancelled request stream's hold goes, unanswered (3.3.3). */
void moqtrun_rdv_drop_stream(
    wired_moqt_hub* hub, const wired_wt_session* s, u64 stream_id) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rdv_on_stream(&hub->rdv[i], s, stream_id)) {
      hub->rdv[i].in_use = 0;
    }
  }
}

/* A closed session's holds go at once: a new session may reuse its handle
 * and stream ids, and must not be answered for them. */
void moqtrun_rdv_drop_wt(wired_moqt_hub* hub, const wired_wt_session* s) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rdv_owned(&hub->rdv[i], s)) {
      hub->rdv[i].in_use = 0;
    }
  }
}

static int moqtrun_rdv_held_here(const wired_moqtrun_peer* p) {
  return p->req && p->req->rdv_held;
}

/* A REQUEST_UPDATE on a held SUBSCRIBE (draft-19 10.9: exactly one answer
 * each, and the first on the stream reads as the SUBSCRIBE's): the hold is
 * answered TIMEOUT first -- the shorter timeout 10.2.6 allows. */
void moqtrun_rdv_settle_early(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!moqtrun_rdv_held_here(p)) {
    return;
  }
  moqtrun_send_request_error(p, MOQTRUN_ERR_TIMEOUT);
  p->req->rdv_held = 0;
  moqtrun_rdv_drop_stream(hub, p->wt, p->req->stream_id);
}

/* draft SS10.6 SUBSCRIBE for a peer-published track: find it and reply
 * SUBSCRIBE_OK with an assigned Track Alias, else DOES_NOT_EXIST. */
static void moqtrun_route_peer_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    wired_span              body) {
  u8                   ns_buf[WIRED_MOQTRUN_MAX_NS];
  moqtrun_key          k     = moqtrun_key_of(&m->name, ns_buf);
  wired_moqtrun_track* track = moqtrun_find_published_track(hub, k);
  if (!track) {
    moqtrun_rdv_miss(hub, p, m, k, body);
    return;
  }
  moqtrun_subscribe_peer_track(hub, p, track, peer_idx, k, m);
}

/* draft SS10.6 SUBSCRIBE: the hub's own tracks answer first (they win
 * over a peer track of the same name), everything else is matched against
 * the peers' PUBLISHed tracks. Caller has already rejected timeout
 * parameters. */
void moqtrun_route_subscribe(
    wired_moqt_hub*         hub,
    wired_moqtrun_peer*     p,
    usz                     peer_idx,
    const moqctl_subscribe* m,
    wired_span              body) {
  if (moqtrun_track_name_matches(&hub->blob_track, m->name.name)) {
    moqtrun_subscribe_blob(hub, p, peer_idx, m);
    return;
  }
  if (moqtrun_track_name_matches(&hub->live.track, m->name.name)) {
    moqtrun_subscribe_live(hub, p, peer_idx, m);
    return;
  }
  moqtrun_route_peer_subscribe(hub, p, peer_idx, m, body);
}

static int moqtrun_ns_field_eq(wired_span f, const char* z, usz n) {
  return f.n == n && !ct_diffn(f.p, (const u8*)z, n);
}

/* draft-19 2.4.2/2.4.3 reserved namespaces: a first Track Namespace
 * field of exactly "." MUST be rejected DOES_NOT_EXIST; ".session"
 * names session-level tracks, and this hub defines none, so every
 * request for one is unrecognized and DOES_NOT_EXIST too. Any other
 * "."-led field is an unrecognized reserved namespace and passes to
 * the application (this hub's normal handling). */
int moqtrun_ns_reserved(const moqctl_ns* ns) {
  if (!ns->n) {
    return 0;
  }
  return moqtrun_ns_field_eq(ns->fields[0], ".", 1) ||
         moqtrun_ns_field_eq(ns->fields[0], ".session", 8);
}

/* draft SS13.3: "Relays will verify the token to ensure that the request
 * is authorized." Every SUBSCRIBE passes here before any track matching
 * (own blob/live tracks and peer tracks alike); a Token Alias already
 * closed the session at decode (moqtrun_take_tok_or_close). 1 + *code
 * when refused. */
int moqtrun_subscribe_refused(
    const wired_moqt_hub* hub, const moqctl_subscribe* m, u64* code) {
  const moqctl_token* t = moqtrun_auth_token_of(&m->params);
  *code                 = MOQCTL_ERR_UNAUTHORIZED;
  if (!hub->authorize_subscribe) {
    return 0;
  }
  return !hub->authorize_subscribe(hub->authorize_ctx, &m->name, t);
}

/* draft-22 16.3 "Preventing Impersonation" (the same MUST in every
 * draft): a relay verifies the publisher may claim the PUBLISH's Full
 * Track Name. Every PUBLISH passes here before any slot is claimed,
 * moqtrun_subscribe_refused's twin. 1 + *code when refused. */
int moqtrun_publish_auth_refused(
    const wired_moqt_hub* hub, const moqctl_publish* m, u64* code) {
  const moqctl_token* t = moqtrun_auth_token_of(&m->params);
  *code                 = MOQCTL_ERR_UNAUTHORIZED;
  if (!hub->authorize_publish) {
    return 0;
  }
  return !hub->authorize_publish(hub->authorize_pub_ctx, &m->name, t);
}
