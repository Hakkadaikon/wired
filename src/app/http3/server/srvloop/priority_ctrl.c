#include "app/http3/server/srvloop/priority_ctrl_impl.h"

static int  ctrl_is_uni_stream_id(u64 stream_id);
static usz  ctrl_skip_len(const stream_frame* sf);
static u64  ctrl_abs_off(const stream_frame* sf);
static int  ctrl_trim_stale(const wired_srvloop* l, u64* abs, wired_span* d);
static void ctrl_store(wired_srvloop* l, u64 abs, wired_span d);

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
int srvloop_ctrl_is_stream_type(u64 type) {
  return type >= FRAME_STREAM_BASE && type <= FRAME_STREAM_BASE + 7;
}

/* RFC 9000 2.1: a client-initiated unidirectional stream has low bits 10. */
static int ctrl_is_uni_stream_id(u64 stream_id) {
  return (stream_id & 0x03) == 2;
}

/* RFC 9114 6.2.1: sf's very first bytes (offset 0) decode as the control
 * stream type (0x00); a mid-stream frame (offset>0) is control traffic iff
 * its stream id matches the one an offset-0 frame already claimed
 * (l->ctrl.open/stream_id, see srvloop_ctrl_claim). */
int srvloop_ctrl_leading_type_is_control(const stream_frame* sf) {
  u64 v;
  usz off = 0;
  if (!varint_take(wired_span_of(sf->data, (usz)sf->length), &off, &v))
    return 0;
  return h3_stream_type_is_control(v);
}

/* 1 if the walked frame decodes into sf as a client uni STREAM frame; the
 * caller still must confirm it is specifically the control stream. */
int srvloop_ctrl_stream_of(u64 type, wired_span frame, stream_frame* sf) {
  return srvloop_ctrl_is_stream_type(type) &&
         frame_get_stream(frame.p, frame.n, sf) &&
         ctrl_is_uni_stream_id(sf->stream_id);
}

/* sf's own bytes that are the leading type varint rather than control-stream
 * payload: the whole varint for the offset-0 frame, none for any later one
 * (the type never reappears mid-stream). */
static usz ctrl_skip_len(const stream_frame* sf) {
  if (sf->offset == 0) return CTRL_TYPE_LEN;
  return 0;
}

/* sf's stream-level offset, shifted back by the type varint's own length so
 * it lands in l->ctrl's post-type-varint coordinate space (offset 0 of
 * l->ctrl.buf is the type varint's first following byte). */
static u64 ctrl_abs_off(const stream_frame* sf) {
  if (sf->offset == 0) return 0;
  return sf->offset - CTRL_TYPE_LEN;
}

/* RFC 9114 6.2.1: land sf's bytes past the leading 0x00 type varint into
 * l->ctrl at their (shifted) offset, raising the high-water mark. Only ever
 * called once srvloop_ctrl_leading_type_is_control (for offset 0) or an
 * established control-stream frame (offset>0) has already confirmed this is the
 * control stream. Mirrors dispatch.c's own gather_one/bump_len shape for
 * req_buf. */
/* Trim the part of *d (at post-type offset *abs) already walked and
 * reclaimed (below l->ctrl.base). 0 when nothing new remains. */
static int ctrl_trim_stale(const wired_srvloop* l, u64* abs, wired_span* d) {
  u64 drop = *abs < l->ctrl.base ? l->ctrl.base - *abs : 0;
  if (drop >= d->n) return 0;
  d->p += drop;
  d->n -= (usz)drop;
  *abs += drop;
  return 1;
}

/* Write d at post-type offset abs into l->ctrl, raising the high-water
 * mark; a chunk past the buffer latches ctrl_overflow (RFC 9114 6.2.1:
 * never a silent truncation). */
static void ctrl_store(wired_srvloop* l, u64 abs, wired_span d) {
  usz off = (usz)(abs - l->ctrl.base);
  if (!bytes_put(wired_mspan_of(l->ctrl.buf, sizeof l->ctrl.buf), &off, d)) {
    l->ctrl_overflow = 1;
    return;
  }
  if (off > l->ctrl.len) l->ctrl.len = off;
}

void srvloop_ctrl_land(wired_srvloop* l, const stream_frame* sf) {
  usz        skip = ctrl_skip_len(sf);
  u64        abs  = ctrl_abs_off(sf);
  wired_span d    = wired_span_of(sf->data + skip, (usz)sf->length - skip);
  if (ctrl_trim_stale(l, &abs, &d)) ctrl_store(l, abs, d);
}

/* Reclaim the walked prefix: slide the unparsed backlog to buf[0]. */
void srvloop_ctrl_compact(wired_srvloop* l) {
  usz p = l->ctrl.parsed;
  bytes_move_down(l->ctrl.buf, l->ctrl.buf + p, l->ctrl.len - p);
  l->ctrl.base += p;
  l->ctrl.len -= p;
  l->ctrl.parsed = 0;
}
