#include "app/moqt/run/moqtrun_impl.h"

/* draft-23 9.2: B sent GOAWAY on the stream of a PUBLISH the hub sent it
 * for a SUBSCRIBE_TRACKS (moqtrun_pubst_goaway): "the sender of the
 * request SHOULD re-issue that specific request on a session at the
 * specified URI (or the current session if no URI is provided), and close
 * the old request stream". The hub is the server, so no URI comes: the
 * sweep sends B a new PUBLISH on a new stream under a new Request ID,
 * then ends the old subscription with PUBLISH_DONE GOING_AWAY, or resets
 * an unanswered old PUBLISH. Without a stream to open the old one stays
 * and a later sweep tries again; a B that sent a GOAWAY on its control
 * stream gets no new request (9.2), so it just stays. */

static int moqtrun_pubst_origin_of(
    const wired_moqtrun_req* st, const wired_moqtrun_req* q) {
  return moqtrun_disc_is(st, MOQCTL_T_SUBSCRIBE_TRACKS) && st->wt == q->wt &&
         st->request_id == q->pub_origin_rid;
}

/* The SUBSCRIBE_TRACKS q's PUBLISH answers, else 0. */
static wired_moqtrun_req* moqtrun_pubst_origin(
    wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_pubst_origin_of(&hub->reqs[i], q)) {
      return &hub->reqs[i];
    }
  }
  return 0;
}

/* The old PUBLISH q to sp closes: its subscription ends GOING_AWAY, an
 * unanswered one (and the fill opened with it) is reset. */
static void moqtrun_pubst_close_old(
    wired_moqt_hub* hub, wired_moqtrun_peer* sp, wired_moqtrun_req* q) {
  wired_moqtrun_track* t = 0;
  wired_moqtrun_sub*   s =
      moqtrun_hub_sub_by_rid(hub, (usz)(sp - hub->peers), q->request_id, &t);
  q->pub_move = 0;
  if (!s) {
    moqtrun_fetches_cancel(hub, sp->wt, q->request_id);
    moqtrun_subtracks_pub_reset(hub, q);
    return;
  }
  moqtrun_sub_done(hub, sp, q, t, s, MOQCTL_DONE_GOING_AWAY);
}

/* The new PUBLISH of t to sp for st went out; 0 leaves q for later. */
static int moqtrun_pubst_resend(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  sp,
    wired_moqtrun_req*   st,
    wired_moqtrun_track* t) {
  wired_moqtrun_req* nq = moqtrun_subtracks_claim_slot(hub, sp, st->request_id);
  if (!nq) {
    return 0;
  }
  if (!moqtrun_subtracks_open_pub(hub, sp, nq, t, st)) {
    nq->in_use = 0;
    return 0;
  }
  moqtrun_subtracks_fill(hub, sp, nq, t, st);
  return 1;
}

static int moqtrun_pubst_can_move(
    const wired_moqtrun_peer*  sp,
    const wired_moqtrun_req*   st,
    const wired_moqtrun_track* t) {
  return moqtrun_up_peer_usable(sp) && st && t;
}

static void moqtrun_pubst_move(wired_moqt_hub* hub, wired_moqtrun_req* q) {
  wired_moqtrun_peer*  sp = moqtrun_find_by_wt(hub, q->wt);
  wired_moqtrun_req*   st = moqtrun_pubst_origin(hub, q);
  wired_moqtrun_track* t  = moqtrun_pubst_track(hub, q->pub_track_tag);
  if (moqtrun_pubst_can_move(sp, st, t) &&
      moqtrun_pubst_resend(hub, sp, st, t)) {
    moqtrun_pubst_close_old(hub, sp, q);
  }
}

static int moqtrun_pubst_moving(const wired_moqtrun_req* q) {
  return q->in_use && q->pub_move;
}

void moqtrun_pubst_moves(wired_moqt_hub* hub) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    if (moqtrun_pubst_moving(&hub->reqs[i])) {
      moqtrun_pubst_move(hub, &hub->reqs[i]);
    }
  }
}
