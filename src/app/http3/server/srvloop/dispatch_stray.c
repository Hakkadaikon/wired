#include "app/http3/server/srvloop/dispatch_impl.h"
#include "app/http3/server/srvloop/srvloop_impl.h"

/* RFC 9000 2.2: STREAM frames arrive in any order, and a packet is
 * acknowledged whatever its frames turn out to be for. A WebTransport
 * stream is told from an ordinary request or uni stream by its leading
 * bytes alone (draft-ietf-webtrans-http3-15 4.3), so a frame that arrives
 * before them cannot be placed yet -- and a browser sends those few bytes
 * as their own packet, which is the one that gets lost. Such frames wait in
 * wired_srvloop.strays until the leading bytes arrive, then land in the
 * stream's window like any other out-of-order frame. */

static int  stray_bidi_unseen(const wired_srvloop* l, u64 stream_id);
static int  stray_bidi_open(const wired_srvloop* l, const stream_frame* sf);
static int  stray_is(const wired_srvloop_stray* e, u64 stream_id);
static int  stray_holds(const wired_srvloop* l, u64 stream_id);
static void stray_keep(wired_srvloop* l, const stream_frame* sf);
static int stray_take(wired_srvloop* l, usz k, u64 stream_id, stream_frame* sf);
static void stray_land_uni(
    wired_srvloop* l, u64 stream_id, wired_srvloop_wt_uni_stream_slot* slot);
static void stray_adopt_uni_at(wired_srvloop* l, u64 stream_id, int i);
static void stray_land_bidi(
    wired_srvloop* l, u64 stream_id, wired_srvloop_wt_stream_slot* slot);
static void stray_adopt_bidi_at(wired_srvloop* l, u64 stream_id, int i);

/* Entry e holds a frame of stream_id. */
static int stray_is(const wired_srvloop_stray* e, u64 stream_id) {
  return e->used && e->stream_id == stream_id;
}

/* 1 if some entry holds a frame of stream_id. */
static int stray_holds(const wired_srvloop* l, u64 stream_id) {
  int held = 0;
  for (usz k = 0; k < WIRED_SRVLOOP_STRAY_MAX; k++) {
    held |= stray_is(&l->strays.e[k], stream_id);
  }
  return held;
}

/* Keep sf in the next entry, overwriting the oldest. A frame too large for
 * an entry is not kept (that stream then stalls, as before). */
static void stray_keep(wired_srvloop* l, const stream_frame* sf) {
  wired_srvloop_stray* e = &l->strays.e[l->strays.next];
  if (sf->length > WIRED_SRVLOOP_STRAY_CAP) {
    return;
  }
  l->strays.n += (u8)!e->used;
  l->strays.next = (u8)((l->strays.next + 1u) % WIRED_SRVLOOP_STRAY_MAX);
  e->stream_id   = sf->stream_id;
  e->offset      = sf->offset;
  e->len         = (u16)sf->length;
  e->fin         = sf->fin;
  e->used        = 1;
  bytes_memcpy(e->data, sf->data, (usz)sf->length);
}

/* A later frame of a client uni stream whose type is not known yet: kept.
 * A stream already typed (control, QPACK, WebTransport, or closed) is not a
 * stray -- its own reassembly, or none, takes the frame. */
void srvloop_stray_keep_uni(wired_srvloop* l, const stream_frame* sf) {
  if (sf->offset != 0 && !srvloop_uni_stream_known(l, sf)) {
    stray_keep(l, sf);
  }
}

/* stream_id has no state at all yet: not a request being reassembled, not
 * closed. */
static int stray_bidi_unseen(const wired_srvloop* l, u64 stream_id) {
  return srvloop_stream_slot_find(l, stream_id) < 0 &&
         !wired_srvloop_closed_has(&l->req_closed, stream_id);
}

/* sf's stream may still turn out to be WebTransport: this is its first
 * frame seen, or an earlier one is already waiting here. */
static int stray_bidi_open(const wired_srvloop* l, const stream_frame* sf) {
  return stray_bidi_unseen(l, sf->stream_id) || stray_holds(l, sf->stream_id);
}

/* A later frame of a client bidi stream not (yet) known as WebTransport:
 * kept while the stream may still be one. The request path takes the frame
 * as well; if the leading bytes then show a request, the copy here is
 * simply overwritten in time. */
void srvloop_stray_keep_bidi(wired_srvloop* l, const stream_frame* sf) {
  if (sf->offset != 0 && stray_bidi_open(l, sf)) {
    stray_keep(l, sf);
  }
}

/* Entry k (counted from the oldest) as a frame, if it is stream_id's: the
 * entry is freed and 1 returned. */
static int stray_take(
    wired_srvloop* l, usz k, u64 stream_id, stream_frame* sf) {
  wired_srvloop_stray* e =
      &l->strays.e[(l->strays.next + k) % WIRED_SRVLOOP_STRAY_MAX];
  if (!stray_is(e, stream_id)) {
    return 0;
  }
  *sf     = (stream_frame){e->stream_id, e->offset, e->len, e->data, e->fin};
  e->used = 0;
  l->strays.n--;
  return 1;
}

/* Every frame kept for stream_id lands in the WT uni slot, oldest first. */
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
