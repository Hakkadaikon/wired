#include "app/http3/server/srvloop/priority_ctrl.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/priupdate.h"
#include "app/http3/core/h3/stream_type.h"
#include "app/http3/server/h3srv/priupdate.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
static int ctrl_is_stream_type(u64 type) {
  return type >= QUIC_FRAME_STREAM_BASE && type <= QUIC_FRAME_STREAM_BASE + 7;
}

/* RFC 9000 2.1: a client-initiated unidirectional stream has low bits 10. */
static int ctrl_is_uni_stream_id(u64 stream_id) {
  return (stream_id & 0x03) == 2;
}

/* RFC 9114 6.2.1: sf's very first bytes (offset 0) decode as the control
 * stream type (0x00); a mid-stream frame (offset>0) is control traffic iff
 * it belongs to a stream whose offset-0 frame already was (the caller tracks
 * that by having reassembled anything into l->ctrl at all -- see
 * wired_srvloop_ctrl_gather's own doc for why offset>0 is accepted
 * unconditionally once id-matched). */
static int ctrl_leading_type_is_control(const quic_stream_frame* sf) {
  u64 v;
  usz off = 0;
  if (!quic_varint_take(quic_span_of(sf->data, (usz)sf->length), &off, &v))
    return 0;
  return quic_h3_stream_type_is_control(v);
}

/* 1 if the walked frame decodes into sf as a client uni STREAM frame; the
 * caller still must confirm it is specifically the control stream. */
static int ctrl_stream_of(u64 type, quic_span frame, quic_stream_frame* sf) {
  return ctrl_is_stream_type(type) &&
         quic_frame_get_stream(frame.p, frame.n, sf) &&
         ctrl_is_uni_stream_id(sf->stream_id);
}

/* RFC 9000 16: the leading 0x00 control type varint's own encoded length --
 * always a single byte. */
#define CTRL_TYPE_LEN 1

/* sf's own bytes that are the leading type varint rather than control-stream
 * payload: the whole varint for the offset-0 frame, none for any later one
 * (the type never reappears mid-stream). */
static usz ctrl_skip_len(const quic_stream_frame* sf) {
  if (sf->offset == 0) return CTRL_TYPE_LEN;
  return 0;
}

/* sf's stream-level offset, shifted back by the type varint's own length so
 * it lands in l->ctrl's post-type-varint coordinate space (offset 0 of
 * l->ctrl.buf is the type varint's first following byte). */
static u64 ctrl_abs_off(const quic_stream_frame* sf) {
  if (sf->offset == 0) return 0;
  return sf->offset - CTRL_TYPE_LEN;
}

/* RFC 9114 6.2.1: land sf's bytes past the leading 0x00 type varint into
 * l->ctrl at their (shifted) offset, raising the high-water mark. Only ever
 * called once ctrl_leading_type_is_control (for offset 0) or an established
 * control-stream frame (offset>0) has already confirmed this is the control
 * stream. Mirrors dispatch.c's own gather_one/bump_len shape for req_buf. */
static void ctrl_land(wired_srvloop* l, const quic_stream_frame* sf) {
  usz skip = ctrl_skip_len(sf);
  usz off  = (usz)ctrl_abs_off(sf);
  if (off >= sizeof l->ctrl.buf) return;
  quic_put_bytes(
      quic_mspan_of(l->ctrl.buf, sizeof l->ctrl.buf), &off,
      quic_span_of(sf->data + skip, (usz)sf->length - skip));
  if (off > l->ctrl.len) l->ctrl.len = off;
}

/* RFC 9218 7.1: apply f (already type-matched to PRIORITY_UPDATE) to its
 * named stream -- 9218-014's id-range check first, 9218-010's buffered
 * apply/pending on success. push is not otherwise supported by this SDK, so
 * a push-variant update is validated (for 9218-014 symmetry) but never
 * applied to anything. */
static void ctrl_apply_priupdate(wired_srvloop* l, const quic_h3_priupdate* f) {
  u16              err;
  quic_h3_priority p;
  if (!wired_h3srv_priupdate_check(1, f->push, f->element_id, &err)) {
    l->priupdate_violation = err;
    return;
  }
  if (f->push) return;
  quic_h3_priority_sfv(f->value, &p);
  wired_srvloop_priority_apply(l, f->element_id, &p);
}

/* Decode the H3 frame at l->ctrl.buf[l->ctrl.parsed..len) and act on it if it
 * is a PRIORITY_UPDATE (either variant); any other frame type is walked past
 * unexamined. Returns bytes consumed, or 0 if the next frame is not yet
 * fully buffered (the caller stops walking until more bytes arrive). */
static usz ctrl_walk_one(wired_srvloop* l, quic_span avail) {
  quic_h3_priupdate f = {0};
  usz               n = quic_h3_priupdate_get(avail, &f);
  if (n) {
    ctrl_apply_priupdate(l, &f);
    return n;
  }
  return quic_h3_frame_get(avail, &(quic_h3_frame){0});
}

/* RFC 9114 7.2: walk every complete HTTP/3 frame newly available in l->ctrl
 * (from l->ctrl.parsed up to l->ctrl.len), advancing parsed past each one;
 * stops at the first incomplete/undecodable frame, leaving its bytes for a
 * later call once more of the stream has arrived. */
static void ctrl_walk(wired_srvloop* l) {
  usz n;
  do {
    quic_span avail = quic_span_of(
        l->ctrl.buf + l->ctrl.parsed, l->ctrl.len - l->ctrl.parsed);
    n = ctrl_walk_one(l, avail);
    l->ctrl.parsed += n;
  } while (n);
}

/* 1 if sf is control-stream traffic this loop has already recognized (or is
 * newly recognizing right now): its leading (offset 0) bytes decode as the
 * control type, or an established control stream (l->ctrl already holds
 * bytes) has a later frame arriving. A later frame before ANY offset-0 frame
 * was seen (l->ctrl.len == 0) belongs to a stream not yet confirmed control
 * and is not control traffic. */
static int ctrl_frame_relevant(
    const wired_srvloop* l, const quic_stream_frame* sf) {
  if (sf->offset == 0) return ctrl_leading_type_is_control(sf);
  return l->ctrl.len != 0;
}

int wired_srvloop_ctrl_gather(wired_srvloop* l, u64 type, quic_span frame) {
  quic_stream_frame sf;
  if (!ctrl_stream_of(type, frame, &sf)) return 0;
  if (!ctrl_frame_relevant(l, &sf)) return 0;
  ctrl_land(l, &sf);
  ctrl_walk(l);
  return 1;
}

/* RFC 9000 2.1: a client-initiated bidirectional (request) stream has low
 * bits 00. */
static int req_is_bidi_stream_id(u64 stream_id) {
  return (stream_id & 0x03) == 0;
}

/* 1 if the walked frame decodes into sf as a client bidi (request) STREAM
 * frame. */
static int req_stream_of(u64 type, quic_span frame, quic_stream_frame* sf) {
  return ctrl_is_stream_type(type) &&
         quic_frame_get_stream(frame.p, frame.n, sf) &&
         req_is_bidi_stream_id(sf->stream_id);
}

/* RFC 9218 7.1 / 9218-013: sf's data names a PRIORITY_UPDATE frame (either
 * variant) at its start -- request/push HTTP/3 framing never nests another
 * frame's bytes ahead of one already begun, so a request stream's PRIORITY_
 * UPDATE is always frame-aligned with whatever STREAM frame first carries
 * it, exactly like request_parse.c's own find_headers walk. */
static int req_carries_priupdate(const quic_stream_frame* sf) {
  quic_h3_priupdate f = {0};
  return quic_h3_priupdate_get(quic_span_of(sf->data, (usz)sf->length), &f) !=
         0;
}

/* RFC 9218 7.1 / 9218-013: latch H3_FRAME_UNEXPECTED for a PRIORITY_UPDATE
 * found on a request stream (wired_h3srv_priupdate_check with
 * on_control_stream=0 always rejects, so the returned code is always
 * H3_FRAME_UNEXPECTED -- called through the same check as ctrl_apply_
 * priupdate for one shared source of truth on the error code). */
static void req_latch_priupdate_violation(wired_srvloop* l) {
  u16 err;
  if (!wired_h3srv_priupdate_check(0, 0, 0, &err)) l->priupdate_violation = err;
}

int wired_srvloop_req_priupdate_gather(
    wired_srvloop* l, u64 type, quic_span frame) {
  quic_stream_frame sf;
  if (!req_stream_of(type, frame, &sf)) return 0;
  if (req_carries_priupdate(&sf)) req_latch_priupdate_violation(l);
  return 1;
}
