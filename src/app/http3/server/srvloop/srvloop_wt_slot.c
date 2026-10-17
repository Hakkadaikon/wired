#include "app/http3/server/srvloop/srvloop_impl.h"

static int wt_slot_is_stale(const wired_srvloop* l, u64 stream_id);
static int wt_slot_free_index(const wired_srvloop* l);

/* Reset (claim) slot i for stream_id, sig_len as given -- shared body of
 * wired_srvloop_wt_slot_claim (sig_len discovered later, from the signal
 * frame) and wired_srvloop_wt_slot_claim_local (sig_len always 0). */
int srvloop_wt_slot_claim_at(wired_srvloop* l, usz i, u64 stream_id) {
  l->wt_streams[i].in_use            = 1;
  l->wt_streams[i].stream_id         = stream_id;
  l->wt_streams[i].sig_len           = 0;
  l->wt_streams[i].sig_have          = 0;
  l->wt_streams[i].sig_pending       = 0;
  l->wt_streams[i].fin               = 0;
  l->wt_streams[i].fin_off           = 0;
  l->wt_streams[i].offered           = 0;
  l->wt_streams[i].wt_session_slot   = -1;
  l->wt_streams[i].delivered_len     = 0;
  l->wt_streams[i].fin_delivered     = 0;
  l->wt_streams[i].credit_advertised = 0;
  l->wt_streams[i].credit_hold       = 0;
  srvloop_wt_window_reset(&l->wt_streams[i].win);
  return (int)i;
}

/* 1 iff client stream_id already ended here (released or refused) -- a
 * claim for it now is a delayed duplicate reopening a stream the app already
 * saw FIN for. Uses the request streams' closed-id bitmap
 * (srvloop_req_closed_mark), which shares the client bidi id space and records
 * exact ids over a 1024-stream window, so a NEW id that merely sorts below
 * older releases is not stale (the old high-watermark rule's silent-loss hole),
 * and an id released long ago still is (a ring of the last 8 forgot it while
 * the table holds more). Server-opened ids (low bit 1) are never stale here:
 * the bitmap indexes stream_id / 4 and would alias them onto client ids. */
static int wt_slot_is_stale(const wired_srvloop* l, u64 stream_id) {
  return !(stream_id & 1) && srvloop_req_closed_has(l, stream_id);
}

/* Record client stream_id as ended (see wt_slot_is_stale). */
void srvloop_wt_closed_mark(wired_srvloop* l, u64 stream_id) {
  if (!(stream_id & 1)) srvloop_req_closed_mark(l, stream_id);
}

/* Claim and reset a free wt_streams slot for stream_id.
 * @return the slot index, or -1 if the table is full or stream_id is stale. */
/* The index of a free wt_streams slot, or -1 if the table is full. */
static int wt_slot_free_index(const wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (!l->wt_streams[i].in_use) return (int)i;
  return -1;
}

int wired_srvloop_wt_slot_claim(wired_srvloop* l, u64 stream_id) {
  int i = wt_slot_is_stale(l, stream_id) ? -1 : wt_slot_free_index(l);
  return i < 0 ? -1 : srvloop_wt_slot_claim_at(l, (usz)i, stream_id);
}

int wired_srvloop_wt_slot_claim_local(wired_srvloop* l, u64 stream_id) {
  int already = wired_srvloop_wt_slot_find(l, stream_id);
  if (already >= 0) return already;
  return wired_srvloop_wt_slot_claim(l, stream_id);
}

void wired_srvloop_wt_refuse(wired_srvloop* l, u64 stream_id) {
  if (wt_slot_is_stale(l, stream_id)) return;
  srvloop_wt_closed_mark(l, stream_id);
  /* RFC 9000 4.6: full only for a peer past MAX_STREAMS (wt_refused) */
  if (l->wt_refused_n < WIRED_SRVLOOP_MAX_STREAMS)
    l->wt_refused[l->wt_refused_n++] = stream_id;
  else
    l->wt_refused_overflow = 1;
}
