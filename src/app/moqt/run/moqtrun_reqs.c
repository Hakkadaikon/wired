#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_req_answered(const wired_moqtrun_req* q);
static int moqtrun_req_orphan(const wired_moqtrun_req* q);
static int moqtrun_req_ending(const wired_moqtrun_req* q);
static int moqtrun_req_may_end(const wired_moqtrun_req* q);
static int moqtrun_req_end_out(wired_moqt_io* io, wired_moqtrun_req* q);
static int moqtrun_req_both_ended(const wired_moqtrun_req* q);
static int moqtrun_pubst_awaiting(const wired_moqtrun_req* q);
static int moqtrun_req_bad_open(const wired_moqtrun_req* q);
static int moqtrun_req_fin_kind(u64 kind);
static int moqtrun_req_fin_cancels(
    const wired_moqtrun_peer* p, const wired_moqtrun_req* q);

/* stream_id's request slot, else a fresh one -- but not for a delivery
 * with no bytes (a FIN trailing a request whose slot is already freed). */
wired_moqtrun_req* moqtrun_req_for(
    wired_moqt_hub* hub, wired_wt_session* s, u64 stream_id, wired_span data) {
  wired_moqtrun_req* q = moqtrun_req_find(hub, s, stream_id);
  if (q) {
    return q;
  }
  if (data.n == 0) {
    return 0;
  }
  return moqtrun_req_admit(hub, s, stream_id);
}

/* ----- request completion (draft 3.3.2) ----- */

/* Answered without establishing anything: the request is complete. */
static int moqtrun_req_answered(const wired_moqtrun_req* q) {
  return q->kind && !q->live && !q->rdv_held;
}

/* The peer ended its side before sending a whole request. */
static int moqtrun_req_orphan(const wired_moqtrun_req* q) {
  return q->fin_in && !q->kind;
}

static int moqtrun_req_ending(const wired_moqtrun_req* q) {
  return moqtrun_req_answered(q) || moqtrun_req_orphan(q);
}

/* 1 iff the hub may end its side now: the request is complete and its
 * answer has left the queue. */
static int moqtrun_req_may_end(const wired_moqtrun_req* q) {
  return !q->fin_out && moqtrun_req_ending(q) &&
         q->send_lens[q->armed_idx ^ 1] == 0;
}

/* Ends the hub's side: a FIN after the answer, or -- nothing was ever
 * sent (an orphan, or a request that could not be decoded) -- a reset
 * with INTERNAL_ERROR (draft 3.3.4). 1 when accepted. */
static int moqtrun_req_end_out(wired_moqt_io* io, wired_moqtrun_req* q) {
  if (q->opened) {
    return io->stream_fin(q->wt, q->stream_id) > 0;
  }
  return io->stream_reset(q->wt, q->stream_id, MOQTRUN_RESET_INTERNAL_ERROR) >
         0;
}

static int moqtrun_req_both_ended(const wired_moqtrun_req* q) {
  return q->fin_in && q->fin_out;
}

/* Sends what is queued, ends the hub's side once the request is complete,
 * and frees the slot when both sides have ended. Replies this small are
 * copied by the transport (srvrun.h: only payloads past its 64 KiB
 * staging are held as views), so freeing the slot never strands bytes. A
 * refused send or end is retried on the next delivery or tick. */
void moqtrun_req_settle(wired_moqt_io* io, wired_moqtrun_req* q) {
  moqtrun_req_flush(io, q->wt, q);
  if (moqtrun_req_may_end(q)) {
    q->fin_out = moqtrun_req_end_out(io, q);
  }
  q->in_use = !moqtrun_req_both_ended(q);
}

/* A hub-opened PUBLISH slot still awaiting its one REQUEST_OK/REQUEST_ERROR
 * (moqtrun_pubst_recv's doc). */
static int moqtrun_pubst_awaiting(const wired_moqtrun_req* q) {
  return q->pub_origin_rid && !q->pub_answered;
}

/* A hub-opened PUBLISH slot awaiting its reply only flushes: settling's
 * "answered without establishing" reading of kind+!live would FIN it
 * early. Once answered it settles like any request (12-27): live while the
 * subscription stands, FINed right after its PUBLISH_DONE (d18 10.11 "A
 * sender SHOULD send FIN on the subscription's bidi stream immediately
 * after sending PUBLISH_DONE"; d19 10.11 / d22 9.9 "the final message
 * before closing the subscription's bidi stream"). */
void moqtrun_reqs_tick_one(wired_moqt_io* io, wired_moqtrun_req* q) {
  if (!q->in_use) {
    return;
  }
  if (moqtrun_pubst_awaiting(q)) {
    moqtrun_req_flush(io, q->wt, q);
    return;
  }
  moqtrun_req_settle(io, q);
}

/* Pushes owed namespace changes, syncs SUBSCRIBE_TRACKS against every
 * published track and upstream SUBSCRIBEs against their waiters, then
 * settles every client-request stream. */
void moqtrun_reqs_tick(wired_moqt_hub* hub) {
  moqtrun_disc_sync(hub);
  moqtrun_subtracks_sync(hub);
  moqtrun_up_sync(hub);
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_REQS; i++) {
    moqtrun_reqs_tick_one(&hub->io, &hub->reqs[i]);
  }
}

/* 1 iff q's first message is still incomplete but its Type is already
 * readable and is no request type. */
static int moqtrun_req_bad_open(const wired_moqtrun_req* q) {
  usz at   = 0;
  u64 type = 0;
  if (q->kind || !moqvi_take(moqtrun_asm_rest(&q->in), &at, &type)) {
    return 0;
  }
  return !moqtrun_req_is_first(type);
}

/* draft 3.3: the opening Type is judged as soon as it is readable -- Object
 * data sent on a bidi stream need never complete a control message. */
void moqtrun_req_check_open(wired_moqt_hub* hub, wired_moqtrun_peer* p) {
  if (!moqtrun_req_bad_open(p->req)) {
    return;
  }
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
}

/* draft-18 6.1 names exactly these two as cancellable by FIN. */
static int moqtrun_req_fin_kind(u64 kind) {
  return kind == MOQNS_T_SUBSCRIBE_NAMESPACE ||
         kind == MOQCTL_T_SUBSCRIBE_TRACKS;
}

/* draft-18 6.1: a FIN cancels a live SUBSCRIBE_NAMESPACE or
 * SUBSCRIBE_TRACKS; draft-19 3.3.2 made every FIN a plain half-close. */
static int moqtrun_req_fin_cancels(
    const wired_moqtrun_peer* p, const wired_moqtrun_req* q) {
  return (moqver_caps(p->ver) & MOQVER_CAP_FIN_CANCEL_NS) && q->live &&
         moqtrun_req_fin_kind(q->kind);
}

/* Records the peer's FIN; on drafts where it is a cancellation the
 * request is cancelled as a RESET_STREAM would (moqtrun_req_cancel). */
void moqtrun_req_note_fin(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, wired_moqtrun_req* q, int fin) {
  q->fin_in |= fin;
  if (fin && moqtrun_req_fin_cancels(p, q)) {
    moqtrun_req_cancel(hub, p, q);
  }
}
