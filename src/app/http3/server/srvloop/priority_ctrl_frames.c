#include "app/http3/core/h3/frame_permit.h"
#include "app/http3/core/h3/settings_check.h"
#include "app/http3/core/h3/settings_dup.h"
#include "app/http3/server/srvloop/priority_ctrl_impl.h"

static void ctrl_wt_initial_set(wired_srvloop* l, u64 id, u64 v);
static int  ctrl_setting_ok(h3_settings_seen* seen, u64 id, u64 v);
static usz  ctrl_settings_walk(wired_srvloop* l, wired_span p);
static void ctrl_on_settings(wired_srvloop* l, const h3_frame* f);
static int  ctrl_one_varint(const h3_frame* f, u64* v);
static int  ctrl_take_id(wired_srvloop* l, const h3_frame* f, u64* v);
static void ctrl_on_goaway(wired_srvloop* l, const h3_frame* f);
static void ctrl_on_cancel_push(wired_srvloop* l, const h3_frame* f);
static void ctrl_on_max_push_id(wired_srvloop* l, const h3_frame* f);
static void ctrl_on_other(wired_srvloop* l, const h3_frame* f);

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

/* RFC 9114 7.2.4.1 (HTTP/2-reserved ids), 7.2.4 (a repeated id), RFC 9297
 * 2.1.1 (SETTINGS_H3_DATAGRAM > 1): 0 if the pair is an H3_SETTINGS_ERROR. */
static int ctrl_setting_ok(h3_settings_seen* seen, u64 id, u64 v) {
  return h3_setting_allowed(id) && h3_setting_h3_datagram_value_ok(id, v) &&
         h3_settings_mark(seen, id);
}

/* Walk p's (Identifier, Value) pairs, checking each and latching the
 * WebTransport initial limits; returns the bytes the complete pairs took. */
static usz ctrl_settings_walk(wired_srvloop* l, wired_span p) {
  h3_settings_seen seen;
  usz              off = 0, done = 0;
  u64              id, v;
  h3_settings_seen_init(&seen);
  while (varint_take(p, &off, &id) && varint_take(p, &off, &v)) {
    srvloop_ctrl_check(l, ctrl_setting_ok(&seen, id, v), H3_SETTINGS_ERROR);
    ctrl_wt_initial_set(l, id, v);
    done = off;
  }
  return done;
}

/* RFC 9114 7.1: a payload ending inside a pair is an H3_FRAME_ERROR. */
static void ctrl_on_settings(wired_srvloop* l, const h3_frame* f) {
  wired_span p = wired_span_of(f->payload, (usz)f->payload_len);
  srvloop_ctrl_check(l, ctrl_settings_walk(l, p) == p.n, H3_FRAME_ERROR);
}

/* 1 iff f's payload is exactly one varint (RFC 9114 7.2.3/7.2.6/7.2.7). */
static int ctrl_one_varint(const h3_frame* f, u64* v) {
  wired_span p   = wired_span_of(f->payload, (usz)f->payload_len);
  usz        off = 0;
  return varint_take(p, &off, v) && off == p.n;
}

/* RFC 9114 7.1: any other payload is an H3_FRAME_ERROR. */
static int ctrl_take_id(wired_srvloop* l, const h3_frame* f, u64* v) {
  int ok = ctrl_one_varint(f, v);
  srvloop_ctrl_check(l, ok, H3_FRAME_ERROR);
  return ok;
}

/* RFC 9114 5.2: a client's GOAWAY carries a Push ID (any value); one larger
 * than a previous GOAWAY's is H3_ID_ERROR (latched in l->h3peer.ctrl). */
static void ctrl_on_goaway(wired_srvloop* l, const h3_frame* f) {
  u64 id;
  if (ctrl_take_id(l, f, &id)) {
    h3_control_goaway(&l->h3peer.ctrl, id);
  }
}

/* RFC 9114 7.2.3: "If a server receives a CANCEL_PUSH frame for a push ID
 * that has not yet been mentioned by a PUSH_PROMISE frame, this MUST be
 * treated as a connection error of type H3_ID_ERROR" -- this server never
 * sends PUSH_PROMISE, so every push ID is unmentioned. */
static void ctrl_on_cancel_push(wired_srvloop* l, const h3_frame* f) {
  u64 id;
  if (ctrl_take_id(l, f, &id)) {
    srvloop_h3_fail(l, H3_ID_ERROR);
  }
}

/* RFC 9114 7.2.7: a MAX_PUSH_ID smaller than a previous one is H3_ID_ERROR. */
static void ctrl_on_max_push_id(wired_srvloop* l, const h3_frame* f) {
  u64 id;
  if (ctrl_take_id(l, f, &id)) {
    srvloop_ctrl_check(l, h3_push_set_max(&l->h3peer.push, id), H3_ID_ERROR);
  }
}

/* RFC 9114 7.2.1/7.2.2/7.2.5/7.2.8: DATA, HEADERS, PUSH_PROMISE and the
 * HTTP/2-only types are H3_FRAME_UNEXPECTED on a control stream; an
 * unknown/grease type is ignored. */
static void ctrl_on_other(wired_srvloop* l, const h3_frame* f) {
  int ok = h3_frame_on_stream(f->type, H3_STREAM_KIND_CONTROL) &&
           h3_frame_recv_ok(f->type);
  srvloop_ctrl_check(l, ok, H3_FRAME_UNEXPECTED);
}

/* The control-stream frame handlers, by frame type (RFC 9114 7.2). */
static void (*const ctrl_frame_fns[])(wired_srvloop*, const h3_frame*) = {
    [H3_FRAME_CANCEL_PUSH] = ctrl_on_cancel_push,
    [H3_FRAME_SETTINGS]    = ctrl_on_settings,
    [H3_FRAME_GOAWAY]      = ctrl_on_goaway,
    [H3_FRAME_MAX_PUSH_ID] = ctrl_on_max_push_id};
#define CTRL_FRAME_FNS_N (sizeof ctrl_frame_fns / sizeof ctrl_frame_fns[0])

void srvloop_ctrl_check(wired_srvloop* l, int ok, u16 code) {
  if (!ok) {
    srvloop_h3_fail(l, code);
  }
}

void srvloop_ctrl_frame(wired_srvloop* l, const h3_frame* f) {
  void (*fn)(wired_srvloop*, const h3_frame*) = ctrl_on_other;
  if (f->type < CTRL_FRAME_FNS_N && ctrl_frame_fns[f->type]) {
    fn = ctrl_frame_fns[f->type];
  }
  fn(l, f);
}
