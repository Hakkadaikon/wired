#include "app/moqt/run/moqtrun_impl.h"

static usz moqtrun_up_sub_put(
    const wired_moqt_hub* hub,
    int                   ver,
    wired_mspan           buf,
    u64                   rid,
    moqtrun_key           k);
static int moqtrun_up_send(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    moqtrun_key         k);
static int moqtrun_rdv_fresh(const wired_moqtrun_rdv* r, moqtrun_key k);
static int moqtrun_rdv_loss_coded(wired_moqt_hub* hub, wired_wt_session* wt);
static int moqtrun_rdv_loses(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, moqtrun_key k);
static void moqtrun_up_wait_single(wired_moqt_hub* hub, wired_moqtrun_rdv* r);
static int  moqtrun_up_needs(wired_moqt_hub* hub, const wired_moqtrun_rdv* r);

/* The SUBSCRIBE for k under Request ID rid, enveloped into buf; its
 * length. */
static usz moqtrun_up_sub_put(
    const wired_moqt_hub* hub,
    int                   ver,
    wired_mspan           buf,
    u64                   rid,
    moqtrun_key           k) {
  moqctl_subscribe m   = {0};
  usz              off = 0;
  m.request_id         = rid;
  m.name.name          = k.name;
  moqctl_ns_take(k.ns, &off, &m.name.ns);
  moqtrun_ngr_upstream(hub, k, &m.params);
  return moqtrun_envelope_put(
      ver, buf, MOQCTL_T_SUBSCRIBE, moqtrun_up_encode_sub, &m);
}

/* SUBSCRIBE for k on a fresh request stream to pp (the hub's next odd
 * Request ID, draft-18 10.1). A waiter's NEW_GROUP_REQUEST rides along
 * (moqtrun_ngr_upstream); nothing else: FORWARD defaults to 1 (9.5
 * "MUST use Forward=1 when subscribing upstream" for a Forward=1
 * subscriber) and no filter is unfiltered; each downstream filter is
 * applied by the relay gates. The QUIC stream limit is the only request
 * limit (draft-18 removed MAX_REQUEST_ID): no stream, no SUBSCRIBE. */
static int moqtrun_up_send(
    wired_moqt_hub*     hub,
    wired_moqtrun_peer* pp,
    wired_moqtrun_up*   u,
    moqtrun_key         k) {
  u8
      msg[WIRED_MOQTRUN_CTL_HDR_MAX + WIRED_MOQTRUN_MAX_NS +
          WIRED_MOQTRUN_MAX_NAME + 32];
  u64 rid = pp->request_id_next;
  usz n =
      moqtrun_up_sub_put(hub, pp->ver, wired_mspan_of(msg, sizeof msg), rid, k);
  i64 sid = hub->io.open_bidi_stream(pp->wt, wired_span_of(msg, n));
  if (sid < 0) {
    return 0;
  }
  pp->request_id_next += 2;
  moqtrun_up_store(u, pp->wt, (u64)sid, rid, k);
  moqtrun_rp_mark(hub, k, pp->wt);
  return 1;
}

/* draft-23 9.2: "the sender of the request SHOULD re-issue that specific
 * request on a session at the specified URI (or the current session if no
 * URI is provided), and close the old request stream". The hub is the
 * server, so no URI comes: u's SUBSCRIBE goes to pp again on a new
 * stream and the old one is cancelled. An Established track keeps its
 * subscribers until the new SUBSCRIBE_OK claims it again. With no stream
 * to open the old request stays (GOAWAY does not impact subscription
 * state). */
void moqtrun_up_reissue(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, wired_moqtrun_up* u) {
  u64 sid = u->stream_id;
  u64 tag = u->track_tag;
  u->move = 0;
  if (!moqtrun_up_send(hub, pp, u, moqtrun_up_key(u))) {
    return;
  }
  u->track_tag = tag;
  hub->io.stream_reset(pp->wt, sid, MOQTRUN_RESET_CANCELLED);
  moqtrun_stream_stop(hub, pp, sid, MOQTRUN_RESET_CANCELLED);
}

/* 1 when an upstream SUBSCRIBE for k went to a's session. */
int moqtrun_up_open(
    wired_moqt_hub* hub, const wired_moqtrun_req* a, moqtrun_key k) {
  wired_moqtrun_up* u = a ? moqtrun_up_free_slot(hub) : 0;
  if (!u) {
    return 0;
  }
  return moqtrun_up_send(hub, moqtrun_find_by_wt(hub, a->wt), u, k);
}

/* ----- the waiters ----- */

/* A SUBSCRIBE waiting for k, not yet answered (a wait for a new path
 * was). */
static int moqtrun_rdv_fresh(const wired_moqtrun_rdv* r, moqtrun_key k) {
  return moqtrun_rdv_matches(r, k) && !r->repath && !r->resume;
}

/* Every SUBSCRIBE waiting for k is answered REQUEST_ERROR code; a wait
 * for a new path keeps waiting. */
void moqtrun_up_refuse_waiters(wired_moqt_hub* hub, moqtrun_key k, u64 code) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rdv_fresh(&hub->rdv[i], k)) {
      moqtrun_rdv_answer(hub, &hub->rdv[i], moqtrun_rdv_do_refuse, 0, code);
    }
  }
}

static int moqtrun_rdv_loss_coded(wired_moqt_hub* hub, wired_wt_session* wt) {
  const wired_moqtrun_peer* p = moqtrun_find_by_wt(hub, wt);
  return p && (moqver_caps(p->ver) & MOQVER_CAP_UP_LOSS);
}

static int moqtrun_rdv_loses(
    wired_moqt_hub* hub, const wired_moqtrun_rdv* r, moqtrun_key k) {
  return moqtrun_rdv_fresh(r, k) && moqtrun_rdv_loss_coded(hub, r->wt);
}

/* The publisher session the upstream SUBSCRIBE for k waited on is lost:
 * a draft-23 waiter is refused INTERNAL_ERROR (12.3). Others stay to be
 * answered DOES_NOT_EXIST once no announcer is left (moqtrun_up_unserved). */
void moqtrun_up_refuse_lost(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rdv_loses(hub, &hub->rdv[i], k)) {
      moqtrun_rdv_answer(
          hub, &hub->rdv[i], moqtrun_rdv_do_refuse, 0,
          MOQCTL_ERR_INTERNAL_ERROR);
    }
  }
}

int moqtrun_up_waiters(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_RDV; i++) {
    if (moqtrun_rdv_matches(&hub->rdv[i], k)) {
      return 1;
    }
  }
  return 0;
}

/* A waiter no upstream can serve: with no announcer left DOES_NOT_EXIST
 * (10.2.6's answer for no publisher), with no stream to open toward one
 * (refused) UNAVAILABLE (draft-23 7.4; EXCESSIVE_LOAD before,
 * moqtrun_send_unavailable). A rendezvous hold keeps waiting for its
 * deadline. */
void moqtrun_up_unserved(
    wired_moqt_hub* hub, wired_moqtrun_rdv* r, int refused) {
  if (!r->up_only) {
    return;
  }
  moqtrun_rdv_answer(
      hub, r, refused ? moqtrun_rdv_do_unavailable : moqtrun_rdv_do_refuse, 0,
      MOQCTL_ERR_DOES_NOT_EXIST);
}

/* 1 iff r waits with no upstream SUBSCRIBE for its track. */
static int moqtrun_up_needs(wired_moqt_hub* hub, const wired_moqtrun_rdv* r) {
  return r->in_use && !moqtrun_up_of_key(hub, moqtrun_up_rdv_key(r));
}

/* One upstream per Full Track Name: the first matching announcer. */
static void moqtrun_up_wait_single(wired_moqt_hub* hub, wired_moqtrun_rdv* r) {
  moqtrun_key        k = moqtrun_up_rdv_key(r);
  wired_moqtrun_req* a;
  if (!moqtrun_up_needs(hub, r)) {
    return;
  }
  a = moqtrun_up_announcer(hub, r->wt, k);
  if (!moqtrun_up_open(hub, a, k)) {
    moqtrun_up_unserved(hub, r, a != 0);
  }
}

void moqtrun_up_wait_one(wired_moqt_hub* hub, wired_moqtrun_rdv* r) {
  if (r->resume) {
    return; /* its track is found: nothing to subscribe upstream */
  }
  if (hub->multi_publisher) {
    moqtrun_up_fan(hub, r);
    return;
  }
  moqtrun_up_wait_single(hub, r);
}

/* ----- ending an upstream subscription ----- */

/* Cancels the hub's request (draft-19 3.3.3, draft-22 6.4.2.3:
 * RESET_STREAM and STOP_SENDING). */
void moqtrun_up_reset(
    wired_moqt_hub* hub, wired_moqtrun_peer* pp, const wired_moqtrun_up* u) {
  hub->io.stream_reset(u->wt, u->stream_id, MOQTRUN_RESET_CANCELLED);
  moqtrun_stream_stop(hub, pp, u->stream_id, MOQTRUN_RESET_CANCELLED);
}
