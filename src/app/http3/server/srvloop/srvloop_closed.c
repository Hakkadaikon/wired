#include "app/http3/server/srvloop/srvloop_impl.h"

/* Record stream_id as closed (RFC 9000 3.2). An id past the 1024-index
 * window slides the window up (whole 64-index words, in one jump however
 * far) until it fits, so a release is never forgotten: the cost is that
 * every index the window
 * leaves behind counts as closed, including a long-lived stream that
 * pinned the floor (a MoQT control stream). That stream keeps working --
 * every lookup finds its live slot before consulting this set -- and an
 * index left behind that was never opened would have to arrive 1024
 * streams late, which RFC 9000 2.1's in-order id use makes implausible. */
void wired_srvloop_closed_mark(wired_srvloop_closed* w, u64 stream_id) {
  u64 idx = stream_id / 4;
  if (idx < w->floor) {
    return;
  }
  if (idx - w->floor >= 1024) {
    srvloop_closed_shift64(w, (idx - w->floor - 1024) / 64 + 1);
  }
  w->bm[(idx - w->floor) / 64] |= (u64)1 << ((idx - w->floor) % 64);
  srvloop_closed_advance(w);
}

/* 1 if stream_id was already closed (see wired_srvloop_closed_mark). */
int wired_srvloop_closed_has(const wired_srvloop_closed* w, u64 stream_id) {
  u64 idx = stream_id / 4;
  if (idx < w->floor) {
    return 1;
  }
  if (idx - w->floor >= 1024) {
    return 0;
  }
  return ((w->bm[(idx - w->floor) / 64] >> ((idx - w->floor) % 64)) & 1) != 0;
}

/* The client bidi (request + WT bidi) closed set. */
void srvloop_req_closed_mark(wired_srvloop* l, u64 stream_id) {
  wired_srvloop_closed_mark(&l->req_closed, stream_id);
}

int srvloop_req_closed_has(const wired_srvloop* l, u64 stream_id) {
  return wired_srvloop_closed_has(&l->req_closed, stream_id);
}

/* Claim and reset a free slot for stream_id.
 * @return the slot index, or -1 if the table is full. */
int srvloop_stream_slot_claim(wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    if (l->streams[i].in_use) {
      continue;
    }
    l->streams[i].in_use         = 1;
    l->streams[i].stream_id      = stream_id;
    l->streams[i].abort_code     = H3_REQUEST_CANCELLED;
    l->streams[i].req_len        = 0;
    l->streams[i].req_fin        = 0;
    l->streams[i].req_done       = 0;
    l->streams[i].req_incomplete = 0;
    l->streams[i].req_over       = 0;
    l->streams[i].qpack_settled  = 0;
    l->streams[i].continue_sent  = 0;
    l->streams[i].continue_len   = 0;
    /* a reused slot's last request must not ask for a 100 again */
    l->streams[i].req.expect_continue = 0;
    srvloop_body_reset(&l->streams[i]);
    l->req_next_id = u64_max(l->req_next_id, stream_id + 4);
    h3_priority_init(&l->streams[i].priority);
    srvloop_pending_priority_consume(l, i);
    return (int)i;
  }
  return -1;
}
