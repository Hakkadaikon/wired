#include "app/http3/server/srvloop/srvloop_impl.h"

static int wt_uni_slot_matches(
    const wired_srvloop_wt_uni_stream_slot* slot, u64 stream_id);
static int wt_uni_slot_is_stale(const wired_srvloop* l, u64 stream_id);
static int wt_uni_slot_free_index(const wired_srvloop* l);
static int wt_uni_slot_claim_at(wired_srvloop* l, usz i, u64 stream_id);

void wired_srvloop_wt_slot_release(wired_srvloop* l, u64 stream_id) {
  int i = wired_srvloop_wt_slot_find(l, stream_id);
  if (i < 0) return;
  l->wt_streams[i].in_use = 0;
  srvloop_wt_closed_mark(l, stream_id);
}

/* 1 if wt uni slot is claimed and reassembling stream_id. */
static int wt_uni_slot_matches(
    const wired_srvloop_wt_uni_stream_slot* slot, u64 stream_id) {
  return slot->in_use && slot->stream_id == stream_id;
}

/* draft-ietf-webtrans-http3-15 4.3: find the wt_uni_streams slot already
 * reassembling stream_id.
 * @return the slot index, or -1 if this stream has no slot yet. */
int wired_srvloop_wt_uni_slot_find(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (wt_uni_slot_matches(&l->wt_uni_streams[i], stream_id)) return (int)i;
  return -1;
}

/* 1 iff stream_id was itself released -- a claim for it now is a delayed
 * duplicate reopening a stream the app already saw FIN for (see
 * wt_uni_closed's doc). */
static int wt_uni_slot_is_stale(const wired_srvloop* l, u64 stream_id) {
  return wired_srvloop_closed_has(&l->wt_uni_closed, stream_id);
}

/* Claim and reset a free wt_uni_streams slot for stream_id. */
/* The index of a free wt_uni_streams slot, or -1 if the table is full. */
static int wt_uni_slot_free_index(const wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (!l->wt_uni_streams[i].in_use) return (int)i;
  return -1;
}

/* Reset (claim) wt_uni_streams slot i for stream_id -- shared body split out
 * of wired_srvloop_wt_uni_slot_claim to keep its own branch count at the
 * gate, mirroring srvloop_wt_slot_claim_at's bidi counterpart. */
static int wt_uni_slot_claim_at(wired_srvloop* l, usz i, u64 stream_id) {
  l->wt_uni_streams[i].in_use            = 1;
  l->wt_uni_streams[i].stream_id         = stream_id;
  l->wt_uni_streams[i].type_len          = 0;
  l->wt_uni_streams[i].sig_have          = 0;
  l->wt_uni_streams[i].sig_pending       = 0;
  l->wt_uni_streams[i].fin               = 0;
  l->wt_uni_streams[i].fin_off           = 0;
  l->wt_uni_streams[i].offered           = 0;
  l->wt_uni_streams[i].wt_session_slot   = -1;
  l->wt_uni_streams[i].delivered_len     = 0;
  l->wt_uni_streams[i].fin_delivered     = 0;
  l->wt_uni_streams[i].credit_advertised = 0;
  l->wt_uni_streams[i].credit_hold       = 0;
  srvloop_wt_window_reset(&l->wt_uni_streams[i].win);
  return (int)i;
}

int wired_srvloop_wt_uni_slot_claim(wired_srvloop* l, u64 stream_id) {
  int i = wt_uni_slot_is_stale(l, stream_id) ? -1 : wt_uni_slot_free_index(l);
  return i < 0 ? -1 : wt_uni_slot_claim_at(l, (usz)i, stream_id);
}
