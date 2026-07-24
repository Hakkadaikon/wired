#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/priority.h"
#include "app/http3/core/h3/priupdate.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"

static const u8 g_priupdate_cli_scid[6] = {'p', 'r', 'i', 'u', 'p', 'd'};

/* Build one STREAM frame (id/offset/fin as given) carrying data into out.
 * Mirrors srvloop_test.c's own lp_stream_frame_at shape (kept local: that
 * one is a static helper in a sibling test TU, not a shared symbol). */
static usz priupdate_stream_frame(
    u8* out, usz cap, u64 id, u64 offset, const u8* data, usz len, u8 fin) {
  quic_stream_frame sf = {id, offset, len, data, fin};
  return quic_frame_put_stream(out, cap, &sf);
}

/* The peer's client uni control stream id (RFC 9000 2.1 low bits 10) used by
 * every test below. */
#define CTRL_STREAM_ID 2

/* Encode {0x00 control-type varint}{PRIORITY_UPDATE frame} into out; returns
 * the combined length (RFC 9114 6.2.1 / RFC 9218 7.1). */
static usz priupdate_ctrl_payload(
    u8* out, usz cap, u64 element_id, int push, const char* pfv, usz pfv_len) {
  usz               off = 1; /* control type 0x00, single byte */
  quic_h3_priupdate f   = {
      push, element_id, quic_span_of((const u8*)pfv, pfv_len)};
  usz n;
  if (cap < 1) return 0;
  out[0] = 0x00;
  n      = quic_h3_priupdate_put(out + off, cap - off, &f);
  if (!n) return 0;
  return off + n;
}

/* Drive one STREAM frame through the dispatcher's side-channel gathering
 * directly (ctx->l set, ctx->s/h3/acc unused by the PRIORITY_UPDATE-only
 * traffic these tests send -- no request completes, so route_dispatch_
 * complete's ctx->s dereference is never reached). */
static void priupdate_dispatch(wired_srvloop* l, const u8* frame, usz len) {
  int                       got = 0;
  wired_h3reqdrive_req      req = {0};
  wired_srvloop_dispatch_in in  = {
      quic_span_of(frame, len), quic_mspan_of(0, 0), quic_mspan_of(0, 0), &got,
      &req};
  wired_srvloop_dispatch(&(wired_srvloop_dispatch_ctx){0, 0, 0, l}, &in);
}

/* RFC 9218 7.1: a request-variant PRIORITY_UPDATE on the client control
 * stream, naming an already-open request stream, updates that stream's
 * priority. */
static void test_srvloop_priupdate_applies_to_open_stream(void) {
  wired_srvloop l;
  u8            payload[64], frame[96];
  usz           plen, flen;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));
  CHECK(wired_srvloop_slot_for(&l, 4) >= 0); /* stream 4 already open */

  plen = priupdate_ctrl_payload(payload, sizeof payload, 4, 0, "u=1", 3);
  CHECK(plen > 0);
  flen = priupdate_stream_frame(
      frame, sizeof frame, CTRL_STREAM_ID, 0, payload, plen, 0);
  CHECK(flen > 0);
  priupdate_dispatch(&l, frame, flen);

  {
    int i = wired_srvloop_slot_for(&l, 4);
    CHECK(i >= 0);
    CHECK(l.streams[i].priority.urgency == 1);
  }
  CHECK(l.priupdate_violation == 0);
}

/* 9218-010: a PRIORITY_UPDATE naming a stream not yet open is buffered and
 * applied once that stream is later claimed. */
static void test_srvloop_priupdate_buffers_for_unopened_stream(void) {
  wired_srvloop l;
  u8            payload[64], frame[96];
  usz           plen, flen;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));

  plen = priupdate_ctrl_payload(payload, sizeof payload, 8, 0, "u=0", 3);
  CHECK(plen > 0);
  flen = priupdate_stream_frame(
      frame, sizeof frame, CTRL_STREAM_ID, 0, payload, plen, 0);
  CHECK(flen > 0);
  priupdate_dispatch(&l, frame, flen);

  /* stream 8 does not exist yet: default priority still applies nowhere */
  CHECK(l.priupdate_violation == 0);

  {
    int i = wired_srvloop_slot_for(&l, 8); /* stream opens now */
    CHECK(i >= 0);
    CHECK(l.streams[i].priority.urgency == 0);
  }
}

/* 9218-013: PRIORITY_UPDATE received on a request stream (not the client
 * control stream) is rejected with H3_FRAME_UNEXPECTED. */
static void test_srvloop_priupdate_on_request_stream_unexpected(void) {
  wired_srvloop l;
  u8            payload[64], frame[96];
  usz           plen, flen;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));

  plen = quic_h3_priupdate_put(
      payload, sizeof payload,
      &(quic_h3_priupdate){0, 4, quic_span_of((const u8*)"u=1", 3)});
  CHECK(plen > 0);
  /* stream 0: a client-initiated bidi (request) stream id. */
  flen = priupdate_stream_frame(frame, sizeof frame, 0, 0, payload, plen, 0);
  CHECK(flen > 0);
  priupdate_dispatch(&l, frame, flen);

  CHECK(l.priupdate_violation == QUIC_H3_FRAME_UNEXPECTED);
}

/* 9218-014: a request-variant PRIORITY_UPDATE naming an element id outside
 * the client bidi id space is H3_ID_ERROR, and no priority is applied. */
static void test_srvloop_priupdate_bad_id_error(void) {
  wired_srvloop l;
  u8            payload[64], frame[96];
  usz           plen, flen;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));
  CHECK(wired_srvloop_slot_for(&l, 4) >= 0);

  /* element id 1 (client uni space, low bits 10) is not a valid Prioritized
   * Element ID for the request variant. */
  plen = priupdate_ctrl_payload(payload, sizeof payload, 1, 0, "u=2", 3);
  CHECK(plen > 0);
  flen = priupdate_stream_frame(
      frame, sizeof frame, CTRL_STREAM_ID, 0, payload, plen, 0);
  CHECK(flen > 0);
  priupdate_dispatch(&l, frame, flen);

  CHECK(l.priupdate_violation == QUIC_H3_ID_ERROR);
  {
    int i = wired_srvloop_slot_for(&l, 4);
    CHECK(l.streams[i].priority.urgency == QUIC_H3_URGENCY_DEFAULT);
  }
}

/* Encode {0x00 control-type varint}{SETTINGS frame} into out; returns the
 * combined length (RFC 9114 6.2.1/7.2.4). Mirrors priupdate_ctrl_payload's
 * shape for the other control-stream frame this file's gather now tracks
 * (WTH3-009/042). */
static usz settings_ctrl_payload(u8* out, usz cap) {
  u8        sf[8];
  quic_obuf sob = quic_obuf_of(sf, sizeof sf);
  usz       i;
  if (cap < 1) return 0;
  if (!quic_h3_frame_put(
          &sob, QUIC_H3_FRAME_SETTINGS, quic_span_of((const u8*)"", 0)))
    return 0;
  if (cap < 1 + sob.len) return 0;
  out[0] = 0x00;
  for (i = 0; i < sob.len; i++) out[1 + i] = sf[i];
  return 1 + sob.len;
}

/* draft-ietf-webtrans-http3-15 SS3.1 (WTH3-009/042): the client's SETTINGS
 * frame, walked off its own control stream, latches
 * l.peer_ctrl.settings_seen -- the signal srvrun.c's WebTransport dispatch
 * gates newly incoming CONNECTs on. */
static void test_srvloop_ctrl_settings_latches_peer_ctrl(void) {
  wired_srvloop l;
  u8            payload[16], frame[32];
  usz           plen, flen;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));
  CHECK(l.peer_ctrl.settings_seen == 0);

  plen = settings_ctrl_payload(payload, sizeof payload);
  CHECK(plen > 0);
  flen = priupdate_stream_frame(
      frame, sizeof frame, CTRL_STREAM_ID, 0, payload, plen, 0);
  CHECK(flen > 0);
  priupdate_dispatch(&l, frame, flen);

  CHECK(l.peer_ctrl.settings_seen == 1);
  CHECK(l.peer_ctrl.error == QUIC_H3_ERR_NONE);
}

/* RFC 9114 7.2.4: a control stream whose first frame is something other than
 * SETTINGS (here, a PRIORITY_UPDATE) latches MISSING_SETTINGS and never sets
 * settings_seen -- the ordering violation is distinguishable from "SETTINGS
 * simply has not arrived yet". */
static void test_srvloop_ctrl_first_frame_not_settings_missing(void) {
  wired_srvloop l;
  u8            payload[64], frame[96];
  usz           plen, flen;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));

  plen = priupdate_ctrl_payload(payload, sizeof payload, 4, 0, "u=1", 3);
  CHECK(plen > 0);
  flen = priupdate_stream_frame(
      frame, sizeof frame, CTRL_STREAM_ID, 0, payload, plen, 0);
  CHECK(flen > 0);
  priupdate_dispatch(&l, frame, flen);

  CHECK(l.peer_ctrl.settings_seen == 0);
  CHECK(l.peer_ctrl.error == QUIC_H3_ERR_MISSING_SETTINGS);
}

/* RFC 9218 10: wired_srvloop_priority_of reads back an open stream's current
 * priority (the same value a scheduler would order sends by) without
 * allocating anything. */
static void test_srvloop_priority_of_open_stream(void) {
  wired_srvloop    l;
  quic_h3_priority p;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));
  CHECK(wired_srvloop_slot_for(&l, 4) >= 0);
  wired_srvloop_priority_apply(
      &l, 4, &(quic_h3_priority){2, 1}); /* u=2, incremental */

  CHECK(wired_srvloop_priority_of(&l, 4, &p) == 1);
  CHECK(p.urgency == 2);
  CHECK(p.incremental == 1);
}

/* A stream id with no open streams[] slot has nothing to read. */
static void test_srvloop_priority_of_unopened_stream(void) {
  wired_srvloop    l;
  quic_h3_priority p;

  CHECK(wired_srvloop_init(
      &l, g_priupdate_cli_scid, sizeof g_priupdate_cli_scid));
  CHECK(wired_srvloop_priority_of(&l, 4, &p) == 0);
}

void test_srvloop_priupdate(void) {
  test_srvloop_priupdate_applies_to_open_stream();
  test_srvloop_priupdate_buffers_for_unopened_stream();
  test_srvloop_priupdate_on_request_stream_unexpected();
  test_srvloop_priupdate_bad_id_error();
  test_srvloop_ctrl_settings_latches_peer_ctrl();
  test_srvloop_ctrl_first_frame_not_settings_missing();
  test_srvloop_priority_of_open_stream();
  test_srvloop_priority_of_unopened_stream();
}
