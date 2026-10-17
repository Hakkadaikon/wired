#include "app/http3/server/srvloop/srvloop_impl.h"

static int  srvloop_body_streaming(const wired_srvloop_stream_slot* slot);
static void srvloop_body_abort(
    wired_srvloop* l, wired_srvloop_stream_slot* slot);

/* RFC 9000 2.2: the slot reassembling stream_id, allocating one on first
 * sight. streams[0] is always the first (and, in the single-request-stream
 * case, only) slot ever claimed, since stream id 0 is the first request
 * stream a connection sees — so the pre-existing single-stream behavior is
 * exactly "the table's entry for stream id 0". A full table drops the
 * stream's frames (returns -1), same as the old fixed capacity of one.
 * Public (not static): dispatch.c routes each request STREAM frame to its
 * own stream's slot through this. */
int wired_srvloop_slot_for(wired_srvloop* l, u64 stream_id) {
  int i = srvloop_stream_slot_find(l, stream_id);
  if (i >= 0) return i;
  if (srvloop_req_closed_has(l, stream_id)) return -2;
  return srvloop_stream_slot_claim(l, stream_id);
}

/* RFC 9000 2.2: free the streams[] slot reassembling stream_id once its
 * response is fully answered and acked -- HTTP/3 never reuses a stream id,
 * so without this the table's 4 slots exhaust after 4 sequential requests
 * on distinct streams. A stream_id with no slot is a no-op. */
/* 1 iff slot's body streams to on_body and has not ended (no fin, no
 * reject, no frame error, no earlier abort). */
static int srvloop_body_streaming(const wired_srvloop_stream_slot* slot) {
  return slot->in_use && slot->body.on && slot->body.state == BODYWIN_OPEN;
}

/* Report slot's unfinished body through on_body_abort, once (the state
 * leaves BODYWIN_OPEN, so a later release or abort is silent). */
static void srvloop_body_abort(
    wired_srvloop* l, wired_srvloop_stream_slot* slot) {
  if (!l->on_body_abort || !srvloop_body_streaming(slot)) return;
  slot->body.state = BODYWIN_ABORTED;
  l->on_body_abort(l->req_ctx, slot->stream_id, slot->abort_code);
}

void wired_srvloop_abort_bodies(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    srvloop_body_abort(l, &l->streams[i]);
}

void wired_srvloop_slot_cancel(wired_srvloop* l, u64 stream_id, u64 code) {
  int i = srvloop_stream_slot_find(l, stream_id);
  if (i >= 0) l->streams[i].abort_code = code;
  wired_srvloop_slot_release(l, stream_id);
}

void wired_srvloop_slot_release(wired_srvloop* l, u64 stream_id) {
  int i = srvloop_stream_slot_find(l, stream_id);
  srvloop_req_closed_mark(l, stream_id);
  if (i < 0) return;
  srvloop_body_abort(l, &l->streams[i]);
  l->req_body_released += l->streams[i].body.base;
  l->streams[i].in_use         = 0;
  l->streams[i].stream_id      = 0;
  l->streams[i].req_len        = 0;
  l->streams[i].req_fin        = 0;
  l->streams[i].req_done       = 0;
  l->streams[i].req_incomplete = 0;
  l->streams[i].req_over       = 0;
  l->streams[i].qpack_settled  = 0;
  srvloop_body_reset(&l->streams[i]);
  h3_priority_init(&l->streams[i].priority);
}
