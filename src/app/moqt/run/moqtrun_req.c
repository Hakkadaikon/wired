#include "app/moqt/run/moqtrun_impl.h"

static void moqtrun_buf_append(u8* buf, usz* len, usz cap, wired_span msg);
static int  moqtrun_flush_idle(const wired_moqtrun_peer* p, int pending_idx);
static int  moqtrun_req_send(
    wired_moqt_io* io, wired_wt_session* s, wired_moqtrun_req* q, wired_span b);

/* ===================== control-message handlers ===================== */

static void moqtrun_buf_append(u8* buf, usz* len, usz cap, wired_span msg) {
  if (*len + msg.n > cap) {
    return;
  }
  bytes_memcpy(buf + *len, msg.p, msg.n);
  *len += msg.n;
}

void moqtrun_req_queue(wired_moqtrun_req* q, wired_span msg) {
  int i = q->armed_idx ^ 1;
  moqtrun_buf_append(
      q->send_bufs[i], &q->send_lens[i], WIRED_MOQTRUN_REQ_SEND_BUF, msg);
}

/* Appends one control message's already-encoded bytes to p's per-dispatch
 * reply queue -- moqtrun.h's send_bufs/armed_idx doc explains why this is
 * the OTHER slot from p->armed_idx, never the armed one: every handler
 * queues here instead of calling stream_send itself, so a dispatch with
 * several replies (e.g. one SUBSCRIBE per other peer) still calls
 * stream_send only once. Silently drops on overflow
 * (WIRED_MOQTRUN_CTL_SEND_BUF is sized for the worst case this hub's own
 * protocol subset can produce, so overflow never happens in practice).
 * A message read from a request stream is answered on that stream
 * instead (draft-ietf-moq-transport-19 10.1: responses travel on the
 * request's bidi stream). */
void moqtrun_queue_reply(wired_moqtrun_peer* p, wired_span msg) {
  int pending_idx = p->armed_idx ^ 1;
  if (p->req) {
    moqtrun_req_queue(p->req, msg);
    return;
  }
  moqtrun_buf_append(
      p->send_bufs[pending_idx], &p->send_lens[pending_idx],
      WIRED_MOQTRUN_CTL_SEND_BUF, msg);
}

/* The request p is handling established a subscription or track. */
void moqtrun_req_mark_live(wired_moqtrun_peer* p) {
  if (p->req) {
    p->req->live = 1;
  }
}

/* The reassembly of the stream p is handling: a request stream's own,
 * else the control stream moqtrun_ctl_rx selected (ctl_asm when no
 * control dispatch is running). */
wired_moqtrun_ctl_asm* moqtrun_cur_asm(wired_moqtrun_peer* p) {
  if (p->req) {
    return &p->req->in;
  }
  return p->rx ? p->rx : &p->ctl_asm;
}

/* Sends every reply queued in p's pending slot, in one stream_send call.
 * Called at both the START and the END of moqtrun_dispatch_ctl_stream (see
 * its own doc for why one call is not enough): a queue can still hold an
 * earlier dispatch's replies when this one begins, because
 * wired_server_wt_stream_send refuses a new round on a keep-open bidi
 * stream until the PREVIOUS round is fully acknowledged (srvrun.c's
 * srvrun_wtsend_appendable) -- an ACK needs at least one more event-loop
 * step than a single app callback ever gets, so two control messages
 * arriving in back-to-back dispatches (e.g. PUBLISH then SUBSCRIBE) can
 * easily straddle that boundary.
 *
 * On success, armed_idx swaps to the slot that was just handed to
 * stream_send (moqtrun.h's own doc on why that slot's bytes must not be
 * touched again until ACKed) -- and appendable() only returns true once
 * the PREVIOUS armed round is fully ACKed, so success here also proves the
 * OLD armed slot is now safe to reuse as the next pending target (it is
 * never handed to stream_send again). On failure (still pending) the
 * pending slot is left untouched so the NEXT dispatch's start-of-call
 * flush retries it, growing with that dispatch's own new replies appended
 * after it. A dispatch that queued nothing (send_lens[pending]==0) sends
 * nothing -- wired_server_wt_stream_send never accepts an empty payload. */
/* Nothing to flush, or nothing may flush yet: the hub's control stream
 * has not opened (its SETUP must be the stream's first bytes, so no
 * reply -- GOAWAY included -- may precede it). */
static int moqtrun_flush_idle(const wired_moqtrun_peer* p, int pending_idx) {
  return !p->ctl_opened || p->send_lens[pending_idx] == 0;
}

void moqtrun_flush_replies(wired_moqt_io* io, wired_moqtrun_peer* p) {
  int pending_idx = p->armed_idx ^ 1;
  if (moqtrun_flush_idle(p, pending_idx)) {
    return;
  }
  int r = io->stream_send(
      p->wt, p->control_stream_id,
      wired_span_of(p->send_bufs[pending_idx], p->send_lens[pending_idx]), 0);
  if (r <= 0) {
    return;
  }
  p->send_lens[p->armed_idx] = 0; /* old armed slot: now safe to reuse */
  p->armed_idx               = pending_idx;
}

/* A request stream's first reply round opens its send side; later rounds
 * append to it. */
static int moqtrun_req_send(
    wired_moqt_io*     io,
    wired_wt_session*  s,
    wired_moqtrun_req* q,
    wired_span         b) {
  if (q->opened) {
    return io->stream_send(s, q->stream_id, b, 0);
  }
  q->opened = io->stream_reply_open(s, q->stream_id, b) > 0;
  return q->opened;
}

/* moqtrun_flush_replies for a request stream's own queue. A successful
 * flush answers every REQUEST_UPDATE coalesced into it at once (draft-19
 * 10.4: "each REQUEST_OK or REQUEST_ERROR response restores one
 * credit"), so the outstanding count resets to 0 rather than ticking
 * down per message. */
void moqtrun_req_flush(
    wired_moqt_io* io, wired_wt_session* s, wired_moqtrun_req* q) {
  int pending_idx = q->armed_idx ^ 1;
  if (q->send_lens[pending_idx] == 0) {
    return;
  }
  wired_span b =
      wired_span_of(q->send_bufs[pending_idx], q->send_lens[pending_idx]);
  if (moqtrun_req_send(io, s, q, b) <= 0) {
    return;
  }
  q->send_lens[q->armed_idx] = 0;
  q->armed_idx               = pending_idx;
  q->pending_updates         = 0;
}

/* Flushes the queue of the stream p is handling. */
void moqtrun_flush_cur(wired_moqt_io* io, wired_moqtrun_peer* p) {
  if (p->req) {
    moqtrun_req_flush(io, p->wt, p->req);
    return;
  }
  moqtrun_flush_replies(io, p);
}
