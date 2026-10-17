#include "app/http3/server/srvloop/priority_ctrl_impl.h"

static void ctrl_apply_priupdate(wired_srvloop* l, const h3_priupdate* f);
static void ctrl_note_frame(wired_srvloop* l, int is_settings);
static void ctrl_wt_initial_set(wired_srvloop* l, u64 id, u64 v);
static void ctrl_latch_settings(wired_srvloop* l, const h3_frame* f);
static void ctrl_note_generic(wired_srvloop* l, const h3_frame* f);
static usz  ctrl_walk_one(wired_srvloop* l, wired_span avail);
static void ctrl_walk(wired_srvloop* l);
static int  ctrl_is_claimed(const wired_srvloop* l, const stream_frame* sf);
static int  ctrl_frame_relevant(wired_srvloop* l, const stream_frame* sf);
static int  req_is_bidi_stream_id(u64 stream_id);
static int  req_stream_of(u64 type, wired_span frame, stream_frame* sf);
static int  req_carries_priupdate(const stream_frame* sf);
static void req_latch_priupdate_violation(wired_srvloop* l);

/* RFC 9218 7.1: apply f (already type-matched to PRIORITY_UPDATE) to its
 * named stream -- 9218-014's id-range check first, 9218-010's buffered
 * apply/pending on success. push is not otherwise supported by this SDK, so
 * a push-variant update is validated (for 9218-014 symmetry) but never
 * applied to anything. */
static void ctrl_apply_priupdate(wired_srvloop* l, const h3_priupdate* f) {
  u16         err;
  h3_priority p;
  if (!wired_h3srv_priupdate_check(1, f->push, f->element_id, &err)) {
    l->priupdate_violation = err;
    return;
  }
  if (f->push) {
    return;
  }
  h3_priority_sfv(f->value, &p);
  wired_srvloop_priority_apply(l, f->element_id, &p);
}

/* RFC 9114 7.2.4: latch one control-stream frame's SETTINGS-ordering state
 * into l->peer_ctrl -- whether the client's SETTINGS has been seen yet
 * (WTH3-009/042: WebTransport dispatch gates newly incoming requests on
 * this). Every control-stream frame updates this, not just SETTINGS, since a
 * MISSING_SETTINGS violation requires seeing that the FIRST frame was
 * something else -- including a PRIORITY_UPDATE, which is why ctrl_walk_one
 * below calls this from both branches, not only its generic-frame
 * fallback. */
static void ctrl_note_frame(wired_srvloop* l, int is_settings) {
  h3_control_frame(&l->peer_ctrl, is_settings);
}

/* draft-ietf-webtrans-http3-16 SS5.5.1-5.5.3: the SETTINGS identifiers
 * latched into l->peer_wt_initial[], index for index. */
static const u64 ctrl_wt_initial_ids[3] = {
    H3_SETTINGS_WT_INITIAL_MAX_STREAMS_UNI,
    H3_SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, H3_SETTINGS_WT_INITIAL_MAX_DATA};

static void ctrl_wt_initial_set(wired_srvloop* l, u64 id, u64 v) {
  for (usz i = 0; i < 3; i++) {
    if (ctrl_wt_initial_ids[i] == id) {
      l->peer_wt_initial[i] = v;
    }
  }
}

/* RFC 9114 7.2.4: walk a SETTINGS payload's (Identifier, Value) pairs and
 * latch the WebTransport initial limits; other identifiers are ignored. */
static void ctrl_latch_settings(wired_srvloop* l, const h3_frame* f) {
  wired_span p   = wired_span_of(f->payload, (usz)f->payload_len);
  usz        off = 0;
  u64        id, v;
  while (varint_take(p, &off, &id) && varint_take(p, &off, &v)) {
    ctrl_wt_initial_set(l, id, v);
  }
}

/* One generic control-stream frame: SETTINGS-ordering state, plus the
 * SETTINGS values themselves when it is the SETTINGS frame. */
static void ctrl_note_generic(wired_srvloop* l, const h3_frame* f) {
  int is_settings = f->type == H3_FRAME_SETTINGS;
  ctrl_note_frame(l, is_settings);
  if (is_settings) {
    ctrl_latch_settings(l, f);
  }
}

/* Decode the H3 frame at l->ctrl.buf[l->ctrl.parsed..len) and act on it if it
 * is a PRIORITY_UPDATE (either variant); any other frame type is walked past
 * unexamined. Either way, its type also latches SETTINGS-ordering state
 * (ctrl_note_frame). Returns bytes consumed, or 0 if the next frame is not
 * yet fully buffered (the caller stops walking until more bytes arrive). */
static usz ctrl_walk_one(wired_srvloop* l, wired_span avail) {
  h3_priupdate f  = {0};
  h3_frame     gf = {0};
  usz          n  = h3_priupdate_get(avail, &f);
  if (n) {
    ctrl_apply_priupdate(l, &f);
    ctrl_note_frame(l, 0); /* PRIORITY_UPDATE is never SETTINGS */
    return n;
  }
  n = h3_frame_get(avail, &gf);
  if (n) {
    ctrl_note_generic(l, &gf);
  }
  return n;
}

/* RFC 9114 7.2: walk every complete HTTP/3 frame newly available in l->ctrl
 * (from l->ctrl.parsed up to l->ctrl.len), advancing parsed past each one;
 * stops at the first incomplete/undecodable frame, leaving its bytes for a
 * later call once more of the stream has arrived. */
static void ctrl_walk(wired_srvloop* l) {
  usz n;
  do {
    wired_span avail = wired_span_of(
        l->ctrl.buf + l->ctrl.parsed, l->ctrl.len - l->ctrl.parsed);
    n = ctrl_walk_one(l, avail);
    l->ctrl.parsed += n;
  } while (n);
}

/* Record sf's stream as THE control stream (first claimant wins -- a later
 * 0x00-typed uni stream is never remixed into the same buffer). Returns 1
 * iff sf's stream is the claimed one. Claiming keys off the offset-0 frame
 * itself, NOT off bytes having landed in l->ctrl: the offset-0 frame may
 * carry the type varint alone (flupke does), leaving ctrl.len at 0 while
 * the stream is nonetheless recognized. */
int srvloop_ctrl_claim(wired_srvloop* l, const stream_frame* sf) {
  if (!l->ctrl.open) {
    l->ctrl.open      = 1;
    l->ctrl.stream_id = sf->stream_id;
  }
  return sf->stream_id == l->ctrl.stream_id;
}

/* A mid-stream (offset>0) frame is control traffic iff it belongs to the
 * claimed control stream -- any other client uni stream's later chunks (a
 * QPACK stream's, say) must not land in the control buffer. */
static int ctrl_is_claimed(const wired_srvloop* l, const stream_frame* sf) {
  return l->ctrl.open && sf->stream_id == l->ctrl.stream_id;
}

/* 1 if sf is control-stream traffic: its leading (offset 0) bytes decode as
 * the control type (claiming the stream), or a later frame arrives on the
 * already-claimed stream. */
static int ctrl_frame_relevant(wired_srvloop* l, const stream_frame* sf) {
  if (sf->offset == 0) {
    return srvloop_ctrl_leading_type_is_control(sf) &&
           srvloop_ctrl_claim(l, sf);
  }
  return ctrl_is_claimed(l, sf);
}

int wired_srvloop_ctrl_gather(wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  if (!srvloop_ctrl_stream_of(type, frame, &sf)) {
    return 0;
  }
  if (!ctrl_frame_relevant(l, &sf)) {
    return 0;
  }
  srvloop_ctrl_land(l, &sf);
  ctrl_walk(l);
  srvloop_ctrl_compact(l);
  return 1;
}

/* RFC 9000 2.1: a client-initiated bidirectional (request) stream has low
 * bits 00. */
static int req_is_bidi_stream_id(u64 stream_id) {
  return (stream_id & 0x03) == 0;
}

/* 1 if the walked frame decodes into sf as a client bidi (request) STREAM
 * frame. */
static int req_stream_of(u64 type, wired_span frame, stream_frame* sf) {
  return srvloop_ctrl_is_stream_type(type) &&
         frame_get_stream(frame.p, frame.n, sf) &&
         req_is_bidi_stream_id(sf->stream_id);
}

/* RFC 9218 7.1 / 9218-013: sf's data names a PRIORITY_UPDATE frame (either
 * variant) at its start -- request/push HTTP/3 framing never nests another
 * frame's bytes ahead of one already begun, so a request stream's PRIORITY_
 * UPDATE is always frame-aligned with whatever STREAM frame first carries
 * it, exactly like request_parse.c's own find_headers walk. */
static int req_carries_priupdate(const stream_frame* sf) {
  h3_priupdate f = {0};
  return h3_priupdate_get(wired_span_of(sf->data, (usz)sf->length), &f) != 0;
}

/* RFC 9218 7.1 / 9218-013: latch H3_FRAME_UNEXPECTED for a PRIORITY_UPDATE
 * found on a request stream (wired_h3srv_priupdate_check with
 * on_control_stream=0 always rejects, so the returned code is always
 * H3_FRAME_UNEXPECTED -- called through the same check as ctrl_apply_
 * priupdate for one shared source of truth on the error code). */
static void req_latch_priupdate_violation(wired_srvloop* l) {
  u16 err;
  if (!wired_h3srv_priupdate_check(0, 0, 0, &err)) {
    l->priupdate_violation = err;
  }
}

int wired_srvloop_req_priupdate_gather(
    wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  if (!req_stream_of(type, frame, &sf)) {
    return 0;
  }
  if (req_carries_priupdate(&sf)) {
    req_latch_priupdate_violation(l);
  }
  return 1;
}
