#include "app/http3/server/srvloop/dispatch.h"

#include "app/datagram/dgdeliver/dg_recv.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
static int is_stream(u64 type) {
  return type >= QUIC_FRAME_STREAM_BASE && type <= QUIC_FRAME_STREAM_BASE + 7;
}

/* RFC 9000 2.1: a STREAM is a client-initiated bidirectional request stream
 * (carrying HTTP/3 HEADERS) iff its low two bits are 0. The 0x2 bit marks a
 * unidirectional stream (HTTP/3 control / QPACK encoder+decoder, RFC 9114 6.2),
 * which curl opens before the request and must NOT be treated as a request. */
static int is_request_stream(u64 stream_id) { return (stream_id & 0x03) == 0; }

/* draft-ietf-webtrans-http3-15 4.3: 1 if this bidi stream's very first bytes
 * (an offset-0 STREAM frame's data) decode as the WT_STREAM signal varint
 * (value 0x41). Only offset 0 is ever checked here — the signal MUST be the
 * stream's leading bytes, so a later (offset>0) frame is never mistaken for
 * one. Truncated/undecodable leading bytes are not the signal (0). */
static int is_wt_stream_signal(quic_span data) {
  u64 v;
  usz off = 0;
  if (!quic_varint_take(data, &off, &v)) return 0;
  return v == QUIC_H3_STREAM_WEBTRANSPORT_BIDI;
}

/* 1 if sf is the stream's first-sighted (offset 0) frame and its leading bytes
 * are the WT_STREAM signal — the one case that overrides an id-based request
 * classification (see sf_is_request below). Any other frame (offset>0) is
 * never checked against the signal, matching "MUST be the leading bytes". */
static int sf_is_wt_signalled(const quic_stream_frame* sf) {
  return sf->offset == 0 &&
         is_wt_stream_signal(quic_span_of(sf->data, (usz)sf->length));
}

/* 1 if sf is a client bidi request stream — i.e. its id classifies as request
 * and it is not a WT bidi stream signalled at its first frame. A WT bidi
 * stream must never be committed to the HTTP/3 request-reassembly path; full
 * routing to a wired_wt_session is Phase 7b future work (see
 * wired_srvloop_dispatch's header doc). Per this call's scope, a WT stream is
 * simply not treated as a request (feed_or_accept's existing "accepted but
 * ignored" path takes it from here). */
static int sf_is_request(const quic_stream_frame* sf) {
  return is_request_stream(sf->stream_id) && !sf_is_wt_signalled(sf);
}

/* 1 if the STREAM frame at `frame` is a client bidi request stream. */
static int stream_is_request(const u8* frame, usz rem) {
  quic_stream_frame sf;
  if (quic_frame_get_stream(frame, rem, &sf) == 0) return 0;
  return sf_is_request(&sf);
}

/* 1 if the walked frame of `type` at `frame` is a client bidi request STREAM.
 */
static int is_request_frame(u64 type, const u8* frame, usz rem) {
  return is_stream(type) && stream_is_request(frame, rem);
}

/* RFC 9114 4.1: hand the (reassembled) request STREAM frame to the HTTP/3
 * request decoder. */
static int dispatch_stream(
    wired_h3srv_state*               h3,
    quic_span                        frame,
    const wired_srvloop_dispatch_in* in) {
  wired_h3srv_req_in rin = {frame, in->scratch};
  if (!wired_h3srv_on_request(h3, &rin, in->req)) return 0;
  *in->got_request = 1;
  return 1;
}

/* Raise the accumulator high-water mark to end, clamped to acc->cap. */
static void bump_len(wired_srvloop_reqacc* acc, usz end) {
  usz hi = end < acc->cap ? end : acc->cap;
  if (hi > *acc->len) *acc->len = hi;
}

/* RFC 9000 2.2: write one request STREAM frame's data into acc->buf at the
 * frame's own offset (offset-indexed reassembly, robust to reordering within
 * acc->cap), advance the high-water mark, and OR its FIN into acc->fin.
 * ponytail: data past acc->cap is truncated. */
static void gather_one(const quic_stream_frame* sf, wired_srvloop_reqacc* acc) {
  usz off = (usz)sf->offset;
  if (off >= acc->cap) return;
  quic_put_bytes(
      quic_mspan_of(acc->buf, acc->cap), &off,
      quic_span_of(sf->data, (usz)sf->length));
  bump_len(acc, (usz)sf->offset + (usz)sf->length);
  *acc->fin |= sf->fin;
}

/* 1 if the walked frame is a request STREAM frame and decodes into sf. */
static int request_stream_of(u64 type, quic_span frame, quic_stream_frame* sf) {
  return is_request_frame(type, frame.p, frame.n) &&
         quic_frame_get_stream(frame.p, frame.n, sf);
}

/* RFC 9000 2.2 / 12.4, RFC 9114 6.2: write every client bidi (request) STREAM
 * frame in this payload into the cross-datagram accumulator at its offset,
 * skipping PADDING/ACK and the unidirectional STREAMs (control / QPACK) curl
 * sends first. Returns 1 if any request-stream frame was seen this datagram. */
static int gather_request(
    const u8* payload, usz len, wired_srvloop_reqacc* acc) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_stream_frame   sf;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    if (request_stream_of(fr.type, quic_span_of(fr.start, fr.remaining), &sf)) {
      gather_one(&sf, acc);
      seen = 1;
    }
  return seen;
}

/* RFC 9000 2.2: the request is complete once FIN closed the stream and it has
 * not already been decoded/answered (curl FINs the request's last STREAM). */
static int request_complete(const wired_srvloop_reqacc* acc) {
  return *acc->fin && !*acc->done;
}

/* 1 if the walked frame at `frame` is ANY client-bidi-id-shaped STREAM frame
 * (low bits 00) — the id space a WT bidi stream shares with request streams,
 * unlike request_stream_of this does NOT exclude a WT-signalled stream, since
 * this is exactly the classifier gather_wt_stream needs to find WT frames
 * request_stream_of deliberately skips. */
static int client_bidi_stream_of(u64 type, quic_span frame, quic_stream_frame* sf) {
  return is_stream(type) && quic_frame_get_stream(frame.p, frame.n, sf) &&
         is_request_stream(sf->stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: this frame is either the stream's leading
 * signal (offset 0, decodes to 0x41) or belongs to a stream already claimed
 * in wt_streams[] by an earlier signal frame. Either way it is WT bidi
 * traffic, not a request. */
static int wt_frame_relevant(const wired_srvloop* l, const quic_stream_frame* sf) {
  return sf_is_wt_signalled(sf) ||
         wired_srvloop_wt_slot_find(l, sf->stream_id) >= 0;
}

/* draft-ietf-webtrans-http3-15 4.3: bytes of THIS frame's own data that are
 * the leading signal, not application data — slot->sig_len for the offset-0
 * signal frame itself (whose data begins with the signal varint, possibly
 * followed by application bytes that landed in the same frame), 0 for any
 * later frame (pure application data, the signal never reappears past
 * offset 0). */
static usz wt_frame_skip(const quic_stream_frame* sf, const wired_srvloop_wt_stream_slot* slot) {
  return sf->offset == 0 ? slot->sig_len : 0;
}

/* Raise slot->len to end, clamped to cap — same shape as dispatch.c's
 * bump_len for the request accumulator. */
static void bump_wt_len(wired_srvloop_wt_stream_slot* slot, usz end, usz cap) {
  usz hi = end < cap ? end : cap;
  if (hi > slot->len) slot->len = hi;
}

/* draft-ietf-webtrans-http3-15 4.3: land one WT bidi STREAM frame's
 * application bytes into slot->buf. Two distinct quantities: `skip` is how
 * many bytes of THIS frame's own data are the signal rather than application
 * data (nonzero only for the offset-0 frame, see wt_frame_skip); `buf_off` is
 * where in slot->buf this frame's application bytes land — every frame's
 * stream-level offset is shifted left by the signal's FULL encoded length
 * (slot->sig_len), since the signal itself never occupies any buf position,
 * not just the offset-0 frame's own skip.
 * ponytail: data past slot->buf's cap is truncated, same policy as the
 * request accumulator's gather_one. */
static void gather_wt_one(const quic_stream_frame* sf, wired_srvloop_wt_stream_slot* slot) {
  usz skip    = wt_frame_skip(sf, slot);
  usz buf_off = (usz)sf->offset - slot->sig_len + skip;
  usz start   = buf_off;
  usz cap     = sizeof slot->buf;
  usz n       = (usz)sf->length - skip;
  if (buf_off >= cap) return;
  quic_put_bytes(
      quic_mspan_of(slot->buf, cap), &buf_off, quic_span_of(sf->data + skip, n));
  bump_wt_len(slot, start + n, cap);
  slot->fin |= sf->fin;
}

/* draft-ietf-webtrans-http3-15 4.3: find-or-claim the wt_streams slot for a
 * newly-signalled stream, recording the signal's own encoded length so
 * gather_wt_one can skip exactly that many bytes. Returns -1 (dropped, table
 * full) exactly like stream_slot_claim's fixed-capacity fallback. */
static int wt_slot_for_signal(wired_srvloop* l, const quic_stream_frame* sf) {
  int i = wired_srvloop_wt_slot_claim(l, sf->stream_id);
  u64 v;
  usz off = 0;
  if (i < 0) return -1;
  quic_varint_take(quic_span_of(sf->data, (usz)sf->length), &off, &v);
  l->wt_streams[i].sig_len = off;
  return i;
}

/* draft-ietf-webtrans-http3-15 4.3: the wt_streams[] slot index for sf, which
 * wt_frame_relevant already confirmed is WT bidi traffic — claim one on the
 * leading signal frame, look up the existing one otherwise. */
static int wt_slot_for(wired_srvloop* l, const quic_stream_frame* sf) {
  if (sf->offset == 0) return wt_slot_for_signal(l, sf);
  return wired_srvloop_wt_slot_find(l, sf->stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: land sf (already confirmed WT bidi
 * traffic) into its slot, claiming one on the leading signal frame. A full
 * table (i<0) still counts the frame as seen, matching stream_slot_claim's
 * fixed-capacity fallback of dropping the data but not the classification. */
static void gather_wt_land(wired_srvloop* l, const quic_stream_frame* sf) {
  int i = wt_slot_for(l, sf);
  if (i >= 0) gather_wt_one(sf, &l->wt_streams[i]);
}

/* draft-ietf-webtrans-http3-15 4.3: if the walked frame at `frame` is WT bidi
 * traffic (wt_frame_relevant), gather it into its slot. Returns 1 if it was
 * (whether or not a slot was available to hold it — matching gather_request's
 * seen semantics). */
static int gather_wt_frame(wired_srvloop* l, u64 type, quic_span frame) {
  quic_stream_frame sf;
  if (!client_bidi_stream_of(type, frame, &sf)) return 0;
  if (!wt_frame_relevant(l, &sf)) return 0;
  gather_wt_land(l, &sf);
  return 1;
}

/* RFC 9000 2.2 / 12.4, draft-ietf-webtrans-http3-15 4.3: write every WT bidi
 * STREAM frame in this payload into its own wt_streams[] slot, at its offset
 * past the signal — independent of whether a request stream is ALSO present
 * in the same payload (a coalesced datagram may carry both). A stream is
 * recognized as WT bidi from its first (offset-0) signal frame; the slot is
 * claimed at that point. Returns 1 if any WT bidi frame was seen. */
static int gather_wt_stream(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    seen |= gather_wt_frame(l, fr.type, quic_span_of(fr.start, fr.remaining));
  return seen;
}

/* RFC 9221 5: copy one decoded DATAGRAM frame's payload into the next free
 * rx_datagrams slot (truncated to its cap, matching this repo's existing
 * truncate-on-overflow policy for fixed buffers). Caller has already checked
 * the queue is not full. */
static void queue_rx_datagram(wired_srvloop* l, quic_span payload) {
  wired_srvloop_rx_datagram* slot = &l->rx_datagrams[l->rx_datagram_n];
  usz cap                         = sizeof slot->buf;
  usz n                           = payload.n < cap ? payload.n : cap;
  usz off                         = 0;
  quic_put_bytes(quic_mspan_of(slot->buf, cap), &off, quic_span_of(payload.p, n));
  slot->len = n;
  l->rx_datagram_n++;
}

/* Decode frame's DATAGRAM payload and queue it; a malformed frame queues
 * nothing. Caller (gather_one_datagram) has already confirmed the type and
 * queue room. */
static void queue_decoded_datagram(wired_srvloop* l, quic_span frame) {
  quic_span payload;
  if (!quic_dgdeliver_extract(frame, &payload)) return;
  queue_rx_datagram(l, payload);
}

/* RFC 9221 5: if the walked frame of `type` at `frame` is a DATAGRAM and the
 * queue has room, decode its payload and queue it. A full queue drops the
 * newly arrived datagram (see rx_datagram_n's doc for why): RFC 9221 datagrams
 * are unreliable, so silently dropping one under sustained load is within
 * spec rather than a bug to fix. */
static void gather_one_datagram(wired_srvloop* l, u64 type, quic_span frame) {
  if (quic_frame_classify(type) != QUIC_FK_DATAGRAM) return;
  if (l->rx_datagram_n >= WIRED_SRVLOOP_MAX_RX_DATAGRAMS) return;
  queue_decoded_datagram(l, frame);
}

/* RFC 9221 5: queue every DATAGRAM frame in this payload into l->rx_datagrams,
 * independent of whether the same payload also carries a request or WT bidi
 * stream frame (a coalesced 1-RTT packet may carry all three). Returns 1 if
 * any DATAGRAM frame was seen this payload (whether or not the queue had room
 * to hold it), so the caller can keep such a payload out of
 * dispatch_non_request's handshake-feed fallback. */
static int gather_rx_datagrams(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (quic_frame_classify(fr.type) == QUIC_FK_DATAGRAM) seen = 1;
    gather_one_datagram(l, fr.type, quic_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9114 4.1: re-wrap the reassembled stream bytes as a single STREAM frame
 * (offset 0) into in->wrap and drive the HTTP/3 request decoder once. req's
 * path/body views end up pointing into in->wrap, so it must be caller-owned
 * storage that outlives this call (a stack local here would dangle by the
 * time the handler reads req). */
static void drive_complete(
    wired_h3srv_state*               h3,
    wired_srvloop_reqacc*            acc,
    const wired_srvloop_dispatch_in* in) {
  quic_stream_frame f  = {0, 0, *acc->len, acc->buf, 1};
  quic_obuf         ob = quic_obuf_of(in->wrap.p, in->wrap.n);
  *acc->done           = 1;
  if (quic_appdata_stream_frame(&f, &ob))
    dispatch_stream(h3, quic_span_of(in->wrap.p, ob.len), in);
}

/* RFC 9000 2.2 / RFC 9114 4.1: accumulate this payload's request-stream frames;
 * once FIN closes the stream, decode the reassembled request exactly once.
 * Returns 1 if a request-stream frame was present (handled), 0 otherwise. */
static int reassemble_and_drive(
    wired_h3srv_state*               h3,
    wired_srvloop_reqacc*            acc,
    const wired_srvloop_dispatch_in* in) {
  if (!gather_request(in->payload.p, in->payload.n, acc)) return 0;
  if (request_complete(acc)) drive_complete(h3, acc, in);
  return 1;
}

/* 1 if the payload carries a STREAM frame of any kind (request or uni). Such a
 * 1-RTT payload belongs to the HTTP/3 path and must never re-enter the
 * handshake via wired_server_feed (RFC 9000 12.4). */
static int has_stream(const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    if (is_stream(fr.type)) return 1;
  return 0;
}

/* 1 if the payload carries at least one walkable frame (non-empty, decodes).
 * An empty/undecodable payload drives nothing. */
static int has_frame(const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, payload, len);
  return quic_framewalk_next(&it, &fr);
}

/* No request stream found. A payload carrying only unidirectional STREAM frames
 * (curl's control / QPACK, RFC 9114 6.2) is accepted but drives no request; a
 * CRYPTO/handshake payload is handed to wired_server_feed. */
static int feed_or_accept(wired_server* s, const u8* payload, usz len) {
  if (has_stream(payload, len)) return 1;
  return wired_server_feed(s, payload, len);
}

static int dispatch_non_request(wired_server* s, const u8* payload, usz len) {
  if (!has_frame(payload, len)) return 0;
  return feed_or_accept(s, payload, len);
}

/* 1 if ctx has a loop to gather WT bidi traffic into (ctx->l != 0) and this
 * payload carried any (draft-ietf-webtrans-http3-15 4.3). A dispatch caller
 * exercising only the request path directly (l == 0) skips WT gathering
 * entirely rather than dereferencing a null loop. */
static int dispatch_gather_wt(const wired_srvloop_dispatch_ctx* ctx, quic_span payload) {
  if (!ctx->l) return 0;
  return gather_wt_stream(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to queue DATAGRAM frames into (ctx->l != 0) and this
 * payload carried any (RFC 9221 5). A dispatch caller exercising only the
 * request path directly (l == 0) skips DATAGRAM gathering entirely rather
 * than dereferencing a null loop. */
static int dispatch_gather_datagrams(
    const wired_srvloop_dispatch_ctx* ctx, quic_span payload) {
  if (!ctx->l) return 0;
  return gather_rx_datagrams(ctx->l, payload.p, payload.n);
}

/* RFC 9000 12.4 / 2.1, RFC 9114 6.2: a payload may lead with PADDING/ACK before
 * its CRYPTO or STREAM frame (curl/quiche do this). A client bidi STREAM drives
 * HTTP/3; unidirectional STREAMs are accepted but ignored; anything else is
 * handed whole to wired_server_feed, whose crecv reassembles a split
 * ClientHello/Finished. A STREAM payload never re-enters the handshake, and
 * neither does a WT bidi stream (draft-ietf-webtrans-http3-15 4.3) or a
 * DATAGRAM frame (RFC 9221 5) — both are gathered independently before either
 * path below, since a coalesced payload may carry all three. */
/* Gather this payload's WT bidi and DATAGRAM frames (each independent of the
 * other, see wired_srvloop_dispatch's doc); 1 if either kind was present. */
static int dispatch_gather_side_channels(
    const wired_srvloop_dispatch_ctx* ctx, quic_span payload) {
  int got_wt = dispatch_gather_wt(ctx, payload);
  int got_dg = dispatch_gather_datagrams(ctx, payload);
  return got_wt | got_dg;
}

int wired_srvloop_dispatch(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  int handled_side = dispatch_gather_side_channels(ctx, in->payload);
  if (reassemble_and_drive(ctx->h3, ctx->acc, in)) return 1;
  if (handled_side) return 1;
  return dispatch_non_request(ctx->s, in->payload.p, in->payload.n);
}

int wired_srvloop_payload_stream_id(quic_span payload, u64* stream_id_out) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_stream_frame   sf;
  quic_framewalk_init(&it, payload.p, payload.n);
  while (quic_framewalk_next(&it, &fr))
    if (request_stream_of(fr.type, quic_span_of(fr.start, fr.remaining), &sf)) {
      *stream_id_out = sf.stream_id;
      return 1;
    }
  return 0;
}
