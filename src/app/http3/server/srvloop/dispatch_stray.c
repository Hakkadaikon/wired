#include "app/http3/server/srvloop/dispatch_impl.h"
#include "app/http3/server/srvloop/srvloop_impl.h"

/* RFC 9000 2.2: STREAM frames arrive in any order, and a packet is
 * acknowledged whatever its frames turn out to be for. A WebTransport
 * stream is told from an ordinary request or uni stream by its leading
 * bytes alone (draft-ietf-webtrans-http3-15 4.3), so a frame that arrives
 * before them cannot be placed yet -- and a browser sends those few bytes
 * as their own packet, which is the one that gets lost. Such frames wait in
 * wired_srvloop.strays until the leading bytes arrive, then land in the
 * stream's window like any other out-of-order frame. A frame that finds no
 * room is not dropped behind an ACK: its packet goes unacknowledged
 * (strays.refused), so the peer sends the frame again. */

static int  stray_bidi_unseen(const wired_srvloop* l, u64 stream_id);
static int  stray_bidi_open(const wired_srvloop* l, const stream_frame* sf);
static int  stray_holds(const wired_srvloop* l, u64 stream_id);
static int  stray_same(const wired_srvloop_stray* e, const stream_frame* sf);
static int  stray_has(const wired_srvloop* l, const stream_frame* sf);
static usz  stray_free(const wired_srvloop* l);
static int  stray_fits(const stream_frame* sf, usz k);
static void stray_put(wired_srvloop* l, usz k, const stream_frame* sf);
static void stray_keep(wired_srvloop* l, const stream_frame* sf);
static void stray_forget(wired_srvloop* l, u64 stream_id);
static void stray_forget_some(wired_srvloop* l, u64 stream_id);

/* Entry e holds a frame of stream_id. */
int srvloop_stray_is(const wired_srvloop_stray* e, u64 stream_id) {
  return e->used && e->stream_id == stream_id;
}

/* 1 if some entry holds a frame of stream_id. */
static int stray_holds(const wired_srvloop* l, u64 stream_id) {
  int held = 0;
  for (usz k = 0; k < WIRED_SRVLOOP_STRAY_MAX; k++) {
    held |= srvloop_stray_is(&l->strays.e[k], stream_id);
  }
  return held;
}

/* Entry e holds this very frame: the peer sent it again. */
static int stray_same(const wired_srvloop_stray* e, const stream_frame* sf) {
  return srvloop_stray_is(e, sf->stream_id) && e->offset == sf->offset;
}

/* 1 if sf is already kept. */
static int stray_has(const wired_srvloop* l, const stream_frame* sf) {
  int has = 0;
  for (usz k = 0; k < WIRED_SRVLOOP_STRAY_MAX; k++) {
    has |= stray_same(&l->strays.e[k], sf);
  }
  return has;
}

/* The first free entry, or WIRED_SRVLOOP_STRAY_MAX when all are in use. */
static usz stray_free(const wired_srvloop* l) {
  usz k = 0;
  while (k < WIRED_SRVLOOP_STRAY_MAX && l->strays.e[k].used) {
    k++;
  }
  return k;
}

static void stray_put(wired_srvloop* l, usz k, const stream_frame* sf) {
  wired_srvloop_stray* e = &l->strays.e[k];
  e->stream_id           = sf->stream_id;
  e->offset              = sf->offset;
  e->len                 = (u16)sf->length;
  e->fin                 = sf->fin;
  e->used                = 1;
  l->strays.n++;
  bytes_memcpy(e->data, sf->data, (usz)sf->length);
}

/* sf fits entry k: k is an entry, and the frame is no larger than one. */
static int stray_fits(const stream_frame* sf, usz k) {
  return sf->length <= WIRED_SRVLOOP_STRAY_CAP && k < WIRED_SRVLOOP_STRAY_MAX;
}

/* Keep sf in a free entry. With none free, or a frame larger than an entry,
 * the packet is marked not to be acknowledged instead (RFC 9000 13.2: only
 * a packet that is acknowledged may be given up by the peer), so no kept
 * entry is ever overwritten. */
static void stray_keep(wired_srvloop* l, const stream_frame* sf) {
  usz k = stray_free(l);
  if (stray_has(l, sf)) {
    return;
  }
  if (!stray_fits(sf, k)) {
    l->strays.refused = 1;
    return;
  }
  stray_put(l, k, sf);
}

/* RFC 9000 13.2: the packet just dispatched may be acknowledged -- none of
 * its frames was refused by the stash. Clears the mark for the next packet.
 */
int srvloop_stray_ackable(wired_srvloop* l) {
  int ok            = !l->strays.refused;
  l->strays.refused = 0;
  return ok;
}

/* stream_id proved not to be WebTransport: its kept frames are dead copies
 * (the request or uni path took the same bytes), so their entries go free. */
static void stray_forget(wired_srvloop* l, u64 stream_id) {
  for (usz k = 0; k < WIRED_SRVLOOP_STRAY_MAX; k++) {
    wired_srvloop_stray* e    = &l->strays.e[k];
    u8                   mine = (u8)srvloop_stray_is(e, stream_id);
    e->used                   = (u8)(e->used & !mine);
    l->strays.n               = (u8)(l->strays.n - mine);
  }
}

/* A later frame of a client uni stream whose type is not known yet: kept.
 * A stream already typed (control, QPACK, WebTransport, or closed) is not a
 * stray -- its own reassembly, or none, takes the frame -- and whatever was
 * kept for it before its type arrived is let go. */
void srvloop_stray_keep_uni(wired_srvloop* l, const stream_frame* sf) {
  if (srvloop_uni_stream_known(l, sf)) {
    stray_forget_some(l, sf->stream_id);
    return;
  }
  if (sf->offset != 0) {
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
 * as well; once the leading bytes arrive and show a request (this is only
 * called for a frame that is not WebTransport), the copies here are let go.
 */
void srvloop_stray_keep_bidi(wired_srvloop* l, const stream_frame* sf) {
  if (sf->offset == 0) {
    stray_forget_some(l, sf->stream_id);
    return;
  }
  if (stray_bidi_open(l, sf)) {
    stray_keep(l, sf);
  }
}

/* stray_forget, skipped while nothing is kept (the usual case: this runs
 * for every later frame of the control and QPACK streams). */
static void stray_forget_some(wired_srvloop* l, u64 stream_id) {
  if (l->strays.n) {
    stray_forget(l, stream_id);
  }
}
