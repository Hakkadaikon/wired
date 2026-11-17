#include "app/http3/server/srvloop/dispatch_impl.h"
#include "app/http3/server/srvloop/srvloop_impl.h"

/* The landing half of the stray stash (dispatch_stray.c): once a stream's
 * leading bytes are whole, the frames kept for it go into its window. */

static int stray_take(wired_srvloop* l, usz k, u64 stream_id, stream_frame* sf);
static void stray_land_uni(
    wired_srvloop* l, u64 stream_id, wired_srvloop_wt_uni_stream_slot* slot);
static void stray_adopt_uni_at(wired_srvloop* l, u64 stream_id, int i);
static void stray_land_bidi(
    wired_srvloop* l, u64 stream_id, wired_srvloop_wt_stream_slot* slot);
static void stray_adopt_bidi_at(wired_srvloop* l, u64 stream_id, int i);

/* Entry k as a frame, if it is stream_id's: the entry is freed and 1
 * returned. */
static int stray_take(
    wired_srvloop* l, usz k, u64 stream_id, stream_frame* sf) {
  wired_srvloop_stray* e = &l->strays.e[k];
  if (!srvloop_stray_is(e, stream_id)) {
    return 0;
  }
  *sf     = (stream_frame){e->stream_id, e->offset, e->len, e->data, e->fin};
  e->used = 0;
  l->strays.n--;
  return 1;
}

/* Every frame kept for stream_id lands in the WT uni slot. */
static void stray_land_uni(
    wired_srvloop* l, u64 stream_id, wired_srvloop_wt_uni_stream_slot* slot) {
  stream_frame sf;
  for (usz k = 0; k < WIRED_SRVLOOP_STRAY_MAX; k++) {
    if (stray_take(l, k, stream_id, &sf)) {
      srvloop_gather_wt_uni_one(&sf, slot);
    }
  }
}

/* Slot i (or none, i < 0) takes its kept frames once its leading signal is
 * whole: only then is the offset of the application bytes known. */
static void stray_adopt_uni_at(wired_srvloop* l, u64 stream_id, int i) {
  if (i < 0 || l->wt_uni_streams[i].sig_pending) {
    return;
  }
  stray_land_uni(l, stream_id, &l->wt_uni_streams[i]);
}

/* A frame of WT uni stream stream_id just landed: frames kept for the
 * stream follow it. Costs one test while nothing is kept. */
void srvloop_stray_adopt_uni(wired_srvloop* l, u64 stream_id) {
  if (l->strays.n) {
    stray_adopt_uni_at(
        l, stream_id, wired_srvloop_wt_uni_slot_find(l, stream_id));
  }
}

/* The same three steps for a WT bidi slot. */
static void stray_land_bidi(
    wired_srvloop* l, u64 stream_id, wired_srvloop_wt_stream_slot* slot) {
  stream_frame sf;
  for (usz k = 0; k < WIRED_SRVLOOP_STRAY_MAX; k++) {
    if (stray_take(l, k, stream_id, &sf)) {
      srvloop_gather_wt_one(&sf, slot);
    }
  }
}

static void stray_adopt_bidi_at(wired_srvloop* l, u64 stream_id, int i) {
  if (i < 0 || l->wt_streams[i].sig_pending) {
    return;
  }
  stray_land_bidi(l, stream_id, &l->wt_streams[i]);
}

void srvloop_stray_adopt_bidi(wired_srvloop* l, u64 stream_id) {
  if (l->strays.n) {
    stray_adopt_bidi_at(l, stream_id, wired_srvloop_wt_slot_find(l, stream_id));
  }
}
