#include "app/http3/server/srvloop/srvloop_impl.h"
#include "common/diag/error/error.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/permit.h"
#include "transport/packet/header/packet/resbits.h"
#include "transport/stream/data/stream/streamstate.h"

static packet_type srvloop_pkt_type(int level, u8 byte0);
static int         srvloop_frame_forbidden(frame_kind k, packet_type pt);
static int srvloop_count_too_big(const framewalk_item* fr, frame_kind k);
static int srvloop_frame_stream_bad(
    const wired_srvloop* l, const framewalk_item* fr, frame_kind k);
static u64 srvloop_frame_value_error(
    const wired_srvloop* l, const framewalk_item* fr, frame_kind k);
static u64 srvloop_frame_error(
    const wired_srvloop* l, const framewalk_item* fr, packet_type pt);
static u64 srvloop_walk_left(const framewalk* it);
static int srvloop_header_bad(u8 byte0, wired_span pl);
static u64 srvloop_frames_error(
    const wired_srvloop* l, wired_span pl, packet_type pt);

/* RFC 9000 12.4 Table 3: the packet type an opened slice is, for the
 * frame-permission matrix; a long header at the application level is 0-RTT. */
static packet_type srvloop_pkt_type(int level, u8 byte0) {
  static const u8 by_level[3] = {PKT_INITIAL, PKT_HANDSHAKE, PKT_1RTT};
  return level == LEVEL_ONERTT && srvloop_app_pkt_is_long(byte0)
             ? PKT_0RTT
             : (packet_type)by_level[level];
}

/* RFC 9000 12.4 / 19.7 / 19.20, RFC 9001 8.3: a frame the packet type does
 * not permit (CRYPTO or ACK in 0-RTT, ...), or one only a server may send
 * (NEW_TOKEN, HANDSHAKE_DONE). */
static int srvloop_frame_forbidden(frame_kind k, packet_type pt) {
  return !frame_permitted(k, pt) || frame_server_recv_forbidden(k);
}

/* RFC 9000 4.6 / 19.11 / 19.14: MAX_STREAMS and STREAMS_BLOCKED share one
 * varint body; a count above 2^60 cannot name a stream id. */
static const u8 SRVLOOP_HAS_COUNT[FK_RESET_STREAM_AT + 1] = {
    [FK_MAX_STREAMS]     = 1,
    [FK_STREAMS_BLOCKED] = 1,
};

static int srvloop_count_too_big(const framewalk_item* fr, frame_kind k) {
  streams_frame f;
  if (!SRVLOOP_HAS_COUNT[k]) {
    return 0;
  }
  return max_streams_decode(fr->start, fr->remaining, &f) &&
         f.max_streams > ((u64)1 << 60);
}

/* RFC 9000 19.4/19.5/19.8/19.10/19.13 (and RESET_STREAM_AT): 1 when the
 * frame needs the client to send on the stream it names, 2 when it needs the
 * client to receive on it; 0 for frames naming no stream. */
static const u8 SRVLOOP_STREAM_DIR[FK_RESET_STREAM_AT + 1] = {
    [FK_STREAM]              = 1,
    [FK_RESET_STREAM]        = 1,
    [FK_STREAM_DATA_BLOCKED] = 1,
    [FK_RESET_STREAM_AT]     = 1,
    [FK_STOP_SENDING]        = 2,
    [FK_MAX_STREAM_DATA]     = 2,
};

/* RFC 9000 19.4..19.13: the named stream runs the wrong way for this frame
 * (a server uni stream carrying client data, a client uni stream told to
 * stop or given credit), or is a server stream not opened yet
 * (streamstate_ok, l->local_opened). The stream id is the varint right after
 * the type in every stream-naming frame; framewalk already measured it. */
static int srvloop_frame_stream_bad(
    const wired_srvloop* l, const framewalk_item* fr, frame_kind k) {
  u64     id;
  usz     t   = varint_decode(fr->start, fr->remaining, &id);
  u8      dir = SRVLOOP_STREAM_DIR[k];
  streams st  = {0, 0};
  if (!dir) {
    return 0;
  }
  varint_decode(fr->start + t, fr->remaining - t, &id);
  st.opened = l->local_opened[(id >> 1) & 1];
  return !streamstate_ok(1, id, dir == 1, &st);
}

static u64 srvloop_frame_value_error(
    const wired_srvloop* l, const framewalk_item* fr, frame_kind k) {
  if (srvloop_count_too_big(fr, k)) {
    return ERR_FRAME_ENCODING_ERROR;
  }
  return srvloop_frame_stream_bad(l, fr, k) ? ERR_STREAM_STATE_ERROR : 0;
}

/* 1 if the ACK frame fr acknowledges a 1-RTT packet number at or past
 * l->tx_pn, the next one to send -- a packet never sent. */
static int srvloop_ack_past_sent(
    const wired_srvloop* l, const framewalk_item* fr) {
  ack_frame f;
  return ack_decode(fr->start, fr->remaining, &f) && f.ranges[0].hi >= l->tx_pn;
}

/* RFC 9000 13.1: "An endpoint SHOULD treat receipt of an acknowledgment
 * for a packet it did not send as a connection error of type
 * PROTOCOL_VIOLATION". Only 1-RTT: l->tx_pn numbers that space. */
static int srvloop_ack_unsent(
    const wired_srvloop*  l,
    const framewalk_item* fr,
    frame_kind            k,
    packet_type           pt) {
  return k == FK_ACK && pt == PKT_1RTT && srvloop_ack_past_sent(l, fr);
}

static u64 srvloop_frame_error(
    const wired_srvloop* l, const framewalk_item* fr, packet_type pt) {
  frame_kind k = frame_classify(fr->type);
  return srvloop_frame_forbidden(k, pt) || srvloop_ack_unsent(l, fr, k, pt)
             ? ERR_PROTOCOL_VIOLATION
             : srvloop_frame_value_error(l, fr, k);
}

/* RFC 9000 12.4 / 19.3.1: the walk stops at an unknown frame type or at a
 * frame its decoder rejects (a truncated field, an ACK range below zero) --
 * either leaves bytes unwalked, a FRAME_ENCODING_ERROR. */
static u64 srvloop_walk_left(const framewalk* it) {
  return it->remaining ? ERR_FRAME_ENCODING_ERROR : 0;
}

/* RFC 9000 12.4: no frames at all; 17.2/17.3.1: Reserved Bits set after
 * header protection was removed. */
static int srvloop_header_bad(u8 byte0, wired_span pl) {
  return pl.n == 0 || !resbits_ok(byte0, (byte0 & 0x80) != 0);
}

/* Every frame of pl checked in order; the first error wins. */
static u64 srvloop_frames_error(
    const wired_srvloop* l, wired_span pl, packet_type pt) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, pl.p, pl.n);
  while (framewalk_next(&it, &fr)) {
    u64 e = srvloop_frame_error(l, &fr, pt);
    if (e) {
      return e;
    }
  }
  return srvloop_walk_left(&it);
}

/* RFC 9000 12.4: the transport error an opened packet's header bits and
 * frames carry, 0 when it is fine. */
u64 srvloop_payload_error(
    const wired_srvloop* l, int level, u8 byte0, wired_span pl) {
  if (srvloop_header_bad(byte0, pl)) {
    return ERR_PROTOCOL_VIOLATION;
  }
  return srvloop_frames_error(l, pl, srvloop_pkt_type(level, byte0));
}
