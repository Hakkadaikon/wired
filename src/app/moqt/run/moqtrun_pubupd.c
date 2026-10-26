#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_peer_has_track(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t);
static wired_wt_session* moqtrun_track_wt(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t);
static int moqtrun_pub_req_kind(const wired_moqtrun_req* q);
static int moqtrun_pub_req_of(
    const wired_moqtrun_req* q, const wired_wt_session* s, u64 rid);
static int moqtrun_track_forwards(const wired_moqtrun_track* t);
static int moqtrun_pub_resume_due(const wired_moqtrun_track* t);
static int moqtrun_upd_answer_ok(const wired_moqtrun_peer* p);

/* ===== the hub's REQUEST_UPDATEs on a publisher's PUBLISH stream =====
 * draft-18/19 10.9, draft-22 9.5: "A subscriber can also send
 * REQUEST_UPDATE to modify parameters of a subscription established with
 * PUBLISH"; its receiver answers each with exactly one REQUEST_OK or
 * REQUEST_ERROR on that stream. The hub sends one to resume a paused
 * PUBLISH (draft-22 7.6) and to relay NEW_GROUP_REQUEST (draft-18
 * 10.2.13, moqtrun_ngr.c).
 * shortcut: only a PUBLISH on its own request stream; one on a legacy
 * single-bidi control stream gets none. */

/* t is one of p's track slots (addresses, as moqtrun_peer_owns). */
static int moqtrun_peer_has_track(
    const wired_moqtrun_peer* p, const wired_moqtrun_track* t) {
  return (usz)t - (usz)p->tracks < sizeof p->tracks;
}

/* The session publishing t, 0 for a hub track. */
static wired_wt_session* moqtrun_track_wt(
    const wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SESSIONS; i++) {
    if (moqtrun_peer_has_track(&hub->peers[i], t)) {
      return hub->peers[i].wt;
    }
  }
  return 0;
}

/* A live client-opened PUBLISH stream. */
static int moqtrun_pub_req_kind(const wired_moqtrun_req* q) {
  return q->in_use && q->kind == MOQCTL_T_PUBLISH && !q->pub_origin_rid;
}

static int moqtrun_pub_req_of(
    const wired_moqtrun_req* q, const wired_wt_session* s, u64 rid) {
  return moqtrun_pub_req_kind(q) && q->wt == s && q->request_id == rid;
}

/* The request stream of the PUBLISH that claimed t, else 0. */
wired_moqtrun_req* moqtrun_pub_req(
    wired_moqt_hub* hub, const wired_moqtrun_track* t) {
  wired_wt_session* s = moqtrun_track_wt(hub, t);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_pub_req_of(&hub->reqs[i], s, t->request_id)) {
      return &hub->reqs[i];
    }
  }
  return 0;
}

/* REQUEST_UPDATE {params} queued on PUBLISH stream q; 0 when it could not
 * be encoded. It goes out with q's next flush (moqtrun_req_settle). */
int moqtrun_pubupd_send(
    wired_moqt_hub* hub, wired_moqtrun_req* q, const moqctl_params* params) {
  u8                  msg[WIRED_MOQTRUN_CTL_REPLY_MAX];
  wired_moqtrun_peer* pp = moqtrun_find_by_wt(hub, q->wt);
  usz                 n = pp ? moqtrun_upd_msg(pp, params, msg, sizeof msg) : 0;
  if (!n) {
    return 0;
  }
  moqtrun_req_queue(q, wired_span_of(msg, n));
  pp->request_id_next += 2;
  q->upd_out++;
  return 1;
}

/* Some Established downstream subscription of t is not paused. */
static int moqtrun_track_forwards(const wired_moqtrun_track* t) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_SUBS; i++) {
    if (moqtrun_sub_forwards(&t->subs[i])) {
      return 1;
    }
  }
  return 0;
}

static int moqtrun_pub_resume_due(const wired_moqtrun_track* t) {
  return t && t->pub_paused && moqtrun_track_forwards(t);
}

/* draft-22 7.6: "If at least one downstream subscriber for the Track is
 * not paused, the Relay MUST resume the upstream subscription with
 * REQUEST_UPDATE, if paused" -- FORWARD 1 on t's PUBLISH stream. Called
 * whenever t's PUBLISH or a downstream subscription changes. */
void moqtrun_pub_resume(wired_moqt_hub* hub, wired_moqtrun_track* t) {
  moqctl_params      params = {0};
  wired_moqtrun_req* q =
      moqtrun_pub_resume_due(t) ? moqtrun_pub_req(hub, t) : 0;
  if (!q) {
    return;
  }
  params.items[0].type = MOQCTL_PARAM_FORWARD;
  params.items[0].enc  = MOQCTL_PENC_UINT8;
  params.items[0].u8v  = 1;
  params.n             = 1;
  t->pub_paused        = !moqtrun_pubupd_send(hub, q, &params);
}

/* ----- the publisher's answers ----- */

/* p's stream is a PUBLISH owing answers to the hub's REQUEST_UPDATEs. */
static int moqtrun_upd_answer_ok(const wired_moqtrun_peer* p) {
  return p->req && p->req->upd_out;
}

/* 1 when type answers one of q's outstanding hub REQUEST_UPDATEs. */
int moqtrun_req_upd_answer(const wired_moqtrun_req* q, u64 type) {
  return q->upd_out &&
         (type == MOQCTL_T_REQUEST_OK || type == MOQCTL_T_REQUEST_ERROR);
}

/* REQUEST_OK: one update answered. Anywhere else (the control stream)
 * it is NOT_SUPPORTED as before. */
void moqtrun_dispatch_upd_ok(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  if (!moqtrun_upd_answer_ok(p)) {
    moqtrun_dispatch_not_supported(hub, p, peer_idx, body);
    return;
  }
  p->req->upd_out--;
}

/* REQUEST_ERROR: the update failed, so its NEW_GROUP_REQUEST is no
 * longer outstanding (draft-18 10.2.13). */
void moqtrun_dispatch_upd_err(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, usz peer_idx, wired_span body) {
  moqctl_request_error e;
  if (!moqtrun_upd_answer_ok(p)) {
    moqtrun_dispatch_not_supported(hub, p, peer_idx, body);
    return;
  }
  p->req->upd_out--;
  p->req->ngr.out =
      (u8)(p->req->ngr.out & !moqtrun_reqerr_take(hub, p, body, &e));
}
