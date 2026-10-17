#include "app/moqt/run/moqtrun_impl.h"

static int  moqtrun_upd_allowed_pub(const wired_moqtrun_req* q);
static int  moqtrun_upd_is_pub(const wired_moqtrun_peer* p);
static int  moqtrun_upd_is_fetch(const wired_moqtrun_peer* p);
static int  moqtrun_upd_is_ns(const wired_moqtrun_peer* p);
static int  moqtrun_upd_is_other(const wired_moqtrun_peer* p);
static int  moqtrun_upd_allowed(const wired_moqtrun_peer* p);
static u32  moqtrun_upd_ns_ctx(const wired_moqtrun_req* q);
static void moqtrun_update_pub(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params);
static void moqtrun_update_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params);
static int moqtrun_update_route_fetch_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params);
static int moqtrun_update_route_other(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params);
static int moqtrun_upd_over_credit(const wired_moqtrun_peer* p);
static int moqtrun_upd_stray(const wired_moqtrun_peer* p);

/* draft-ietf-moq-transport-19 10.9.1 / draft-22 9.5.1: a failed update of
 * a namespace request closes its bidi stream -- the request ends (a
 * PUBLISH_NAMESPACE is withdrawn, a SUBSCRIBE_NAMESPACE owes no
 * NAMESPACE_DONE any more, a SUBSCRIBE_TRACKS opens no more PUBLISHes)
 * and the hub FINs once its answer is out (3.3.2). */
void moqtrun_upd_close_ns(wired_moqtrun_req* q) {
  if (!q || !moqtrun_kind_is_ns(q->kind)) return;
  q->live = 0;
  bytes_memset(q->ns_seen, 0, sizeof q->ns_seen);
}

/* q is a client-opened PUBLISH (its sender's own request). */
static int moqtrun_upd_allowed_pub(const wired_moqtrun_req* q) {
  return q && q->kind == MOQCTL_T_PUBLISH && !q->pub_origin_rid;
}

/* A SUBSCRIBE, or a PUBLISH the hub opened (SUBSCRIBE_TRACKS): d18/d19
 * 10.9, d22 9.5 "A subscriber can also send REQUEST_UPDATE to modify
 * parameters of a subscription established with PUBLISH" -- updated like a
 * SUBSCRIBE's (moqtrun_pubst_update). */
int moqtrun_upd_is_sub(const wired_moqtrun_peer* p) {
  return p->req &&
         (p->req->kind == MOQCTL_T_SUBSCRIBE || p->req->pub_origin_rid);
}

/* draft-18/19 10.9, draft-22 9.5: "The sender of a request (SUBSCRIBE,
 * PUBLISH, FETCH, ...) can later send a REQUEST_UPDATE" -- every draft
 * lets a publisher update its own PUBLISH. */
static int moqtrun_upd_is_pub(const wired_moqtrun_peer* p) {
  return moqtrun_upd_allowed_pub(p->req);
}

/* draft-ietf-moq-transport-19 10.9: the sender of a FETCH may REQUEST_UPDATE
 * it (e.g. SUBSCRIBER_PRIORITY, 10.2.5). */
static int moqtrun_upd_is_fetch(const wired_moqtrun_peer* p) {
  return p->req && p->req->kind == MOQFETCH_T_FETCH;
}

/* draft-ietf-moq-transport-19 10.9: the sender of a PUBLISH_NAMESPACE or
 * SUBSCRIBE_NAMESPACE may REQUEST_UPDATE it (10.9.1 Updating Namespace
 * Subscriptions covers the latter's TRACK_NAMESPACE_PREFIX). */
static int moqtrun_upd_is_ns(const wired_moqtrun_peer* p) {
  return p->req && moqtrun_kind_is_ns(p->req->kind);
}

/* moqtrun_upd_allowed's non-subscription half, split out to keep each
 * predicate's branch budget small. */
static int moqtrun_upd_is_other(const wired_moqtrun_peer* p) {
  return moqtrun_upd_is_pub(p) || moqtrun_upd_is_fetch(p) ||
         moqtrun_upd_is_ns(p);
}

static int moqtrun_upd_allowed(const wired_moqtrun_peer* p) {
  return moqtrun_upd_is_sub(p) || moqtrun_upd_is_other(p);
}

/* moqtrun_upd_ctx's namespace half: SUBSCRIBE_NAMESPACE,
 * SUBSCRIBE_TRACKS and PUBLISH_NAMESPACE each have their own ctx bit
 * (draft-22 9.5). */
static u32 moqtrun_upd_ns_ctx(const wired_moqtrun_req* q) {
  if (q->kind == MOQNS_T_SUBSCRIBE_NAMESPACE)
    return MOQCTL_PCTX_UPDATE_SUBSCRIBE_NAMESPACE;
  if (q->kind == MOQCTL_T_SUBSCRIBE_TRACKS)
    return MOQCTL_PCTX_UPDATE_SUBSCRIBE_TRACKS;
  return MOQCTL_PCTX_UPDATE_PUBLISH_NAMESPACE;
}

/* The MOQCTL_PCTX_UPDATE_* bit a decode must check the update's parameters
 * against, by the request kind riding the stream (10.2.x "MAY appear in"
 * is split the same way). */
u32 moqtrun_upd_ctx(const wired_moqtrun_peer* p) {
  if (moqtrun_upd_is_fetch(p)) return MOQCTL_PCTX_UPDATE_FETCH;
  if (moqtrun_upd_is_ns(p)) return moqtrun_upd_ns_ctx(p->req);
  return MOQCTL_PCTX_UPDATE_SUBSCRIPTION;
}

/* A publisher's update of its own PUBLISH (10.9): the parameters are vetted as
 * a subscription's would be; the hub models no publisher-side state they would
 * move, so an acceptable update is REQUEST_OK and nothing else. */
static void moqtrun_update_pub(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  /* SWITCH_FROM (moqtswitch.c) names subscriptions only */
  u64 code = moqtsw_pub_refusal(params, moqtrun_params_refusal(params));
  (void)hub;
  if (code != MOQTRUN_REQ_ACCEPT) {
    moqtrun_send_request_error(p, code);
    return;
  }
  moqtrun_queue_request_ok(p, 0);
}

/* A REQUEST_UPDATE of a FETCH (10.9, e.g. SUBSCRIBER_PRIORITY 10.2.5):
 * the hub models no FETCH-serving state the admitted parameters would
 * move, and none of them can fail it (a Token Alias already closed the
 * session at decode), so it is REQUEST_OK and nothing else. */
static void moqtrun_update_fetch(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  (void)hub;
  (void)params;
  moqtrun_queue_request_ok(p, 0);
}

/* moqtrun_update_route_other's FETCH-or-namespace half. 1 iff routed. */
static int moqtrun_update_route_fetch_ns(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  if (moqtrun_upd_is_fetch(p)) {
    moqtrun_update_fetch(hub, p, params);
    return 1;
  }
  if (moqtrun_upd_is_ns(p)) {
    moqtrun_update_ns(hub, p, p->req, params);
    return 1;
  }
  return 0;
}

/* moqtrun_update_route's non-subscription request kinds (everything but
 * the common-case SUBSCRIBE, kept separate to stay within one function's
 * branch budget). 1 iff p's request matched one and was routed. */
static int moqtrun_update_route_other(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, const moqctl_params* params) {
  if (moqtrun_upd_is_pub(p)) {
    moqtrun_update_pub(hub, p, params);
    return 1;
  }
  return moqtrun_update_route_fetch_ns(hub, p, params);
}

void moqtrun_update_route(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    usz                  peer_idx,
    const moqctl_params* params,
    u64                  rid) {
  if (moqtrun_fill_malformed(hub, p, params)) return;
  if (moqtrun_update_route_other(hub, p, params)) return;
  moqtrun_update_sub(hub, p, peer_idx, params, rid);
}

/* draft-ietf-moq-transport-19 10.3.1.7, draft-22 9.1.7: a request stream
 * already holding MAX_REQUEST_UPDATES outstanding (received, not yet
 * answered by a flushed reply) REQUEST_UPDATEs closes the session on one
 * more. draft-18 has no such limit (nor advertises one, moqtrun_setup_limits).
 */
static int moqtrun_upd_over_credit(const wired_moqtrun_peer* p) {
  return (moqver_caps(p->ver) & MOQVER_CAP_MAX_REQUEST_UPDATES) &&
         p->req->pending_updates >= WIRED_MOQTRUN_MAX_REQ_UPDATES;
}

/* d19 10.9 / d22 9.5: "An endpoint that receives a REQUEST_UPDATE other
 * than in the two cases above MUST close the session with a
 * PROTOCOL_VIOLATION" -- on the control stream it updates no request (a
 * TRACK_STATUS stream already closes in moqtrun_req_update_ok). d18 10.9
 * has no such sentence. */
static int moqtrun_upd_stray(const wired_moqtrun_peer* p) {
  return !p->req && (moqver_caps(p->ver) & MOQVER_CAP_UPDATE_STRAY_CLOSE);
}

/* A REQUEST_UPDATE of a kind the hub does not update: closed when stray,
 * else (d18's control stream) NOT_SUPPORTED. */
void moqtrun_upd_refuse(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (moqtrun_upd_stray(p)) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
  moqtrun_upd_close_ns(p->req);
}

/* Rejects (and signals) a REQUEST_UPDATE that must not reach decode: not
 * an allowed request kind, or its stream is already over credit. */
int moqtrun_upd_refused(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!moqtrun_upd_allowed(p)) {
    moqtrun_upd_refuse(hub, p);
    return 1;
  }
  if (moqtrun_upd_over_credit(p)) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_TOO_MANY_REQUEST_UPDATES);
    return 1;
  }
  return 0;
}
