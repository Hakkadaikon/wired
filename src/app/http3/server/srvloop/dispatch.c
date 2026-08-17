#include "app/http3/server/srvloop/dispatch.h"

#include "app/datagram/datagram/dgcheck.h"
#include "app/datagram/dgdeliver/dg_recv.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/stream_type.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/peer.h"
#include "app/http3/server/h3srv/respond.h"
#include "app/http3/server/hq09/hq09.h"
#include "app/http3/server/srvloop/priority_ctrl.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/qpack/qpackdyn/enc_stream.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"
#include "common/platform/qlog/qlog.h"
#include "common/platform/qlog/qlogevent.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/dispatch.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/stream/data/appdata/stream_send.h"
#include "transport/stream/data/maxstreams/maxstreams.h"

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
static int is_wt_stream_signal(wired_span data) {
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
         is_wt_stream_signal(wired_span_of(sf->data, (usz)sf->length));
}

/* draft-ietf-webtrans-http3-15 4.3: this frame is either the stream's leading
 * signal (offset 0, decodes to 0x41) or belongs to a stream already claimed
 * in wt_streams[] by an earlier signal frame. Either way it is WT bidi
 * traffic, not a request. l may be 0 (a caller exercising only the request
 * path directly, see wired_srvloop_dispatch_ctx's doc) — a stream can only be
 * ALREADY claimed via a loop that does not exist, so only the offset-0 signal
 * check applies then. */
static int wt_frame_relevant(
    const wired_srvloop* l, const quic_stream_frame* sf) {
  if (sf_is_wt_signalled(sf)) return 1;
  return l && wired_srvloop_wt_slot_find(l, sf->stream_id) >= 0;
}

/* 1 if sf is a client bidi request stream — i.e. its id classifies as request
 * and it is not WT bidi traffic (wt_frame_relevant: either this frame is the
 * leading 0x41 signal, or an earlier frame already claimed this stream in
 * l->wt_streams[]). A WT bidi stream must never be committed to the HTTP/3
 * request-reassembly path, at ANY offset — checking only offset 0 here would
 * let a WT stream's post-signal continuation frame (offset>0) be misread as
 * request data (draft-ietf-webtrans-http3-15 4.3's leading-bytes requirement
 * is about where the SIGNAL may appear, not about which frames of an already-
 * classified stream still count as application data). Full routing to a
 * wired_wt_session is Phase 7b future work (see wired_srvloop_dispatch's
 * header doc); per this call's scope, a WT stream is simply not treated as a
 * request (feed_or_accept's existing "accepted but ignored" path takes it
 * from here). */
static int sf_is_request(const wired_srvloop* l, const quic_stream_frame* sf) {
  return is_request_stream(sf->stream_id) && !wt_frame_relevant(l, sf);
}

/* 1 if the STREAM frame at `frame` is a client bidi request stream. */
static int stream_is_request(const wired_srvloop* l, const u8* frame, usz rem) {
  quic_stream_frame sf;
  if (quic_frame_get_stream(frame, rem, &sf) == 0) return 0;
  return sf_is_request(l, &sf);
}

/* 1 if the walked frame of `type` at `frame` is a client bidi request STREAM.
 */
static int is_request_frame(
    const wired_srvloop* l, u64 type, const u8* frame, usz rem) {
  return is_stream(type) && stream_is_request(l, frame, rem);
}

/* RFC 9114 4.1: hand the (reassembled) request STREAM frame to the HTTP/3
 * request decoder. */
static int dispatch_stream(
    wired_h3srv_state*               h3,
    wired_span                       frame,
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
      wired_mspan_of(acc->buf, acc->cap), &off,
      wired_span_of(sf->data, (usz)sf->length));
  bump_len(acc, (usz)sf->offset + (usz)sf->length);
  *acc->fin |= sf->fin;
}

/* 1 if the walked frame is a request STREAM frame and decodes into sf. l is
 * threaded through to is_request_frame so a WT bidi stream's continuation
 * frame (offset>0, already claimed in l->wt_streams[]) is excluded here too,
 * not just its own offset-0 signal frame. */
static int request_stream_of(
    const wired_srvloop* l, u64 type, wired_span frame, quic_stream_frame* sf) {
  return is_request_frame(l, type, frame.p, frame.n) &&
         quic_frame_get_stream(frame.p, frame.n, sf);
}

/* RFC 9000 2.2 / 12.4, RFC 9114 6.2: write every client bidi (request) STREAM
 * frame in this payload into the cross-datagram accumulator at its offset,
 * skipping PADDING/ACK and the unidirectional STREAMs (control / QPACK) curl
 * sends first. Returns 1 if any request-stream frame was seen this datagram. */
static int gather_request(
    const wired_srvloop*  l,
    const u8*             payload,
    usz                   len,
    wired_srvloop_reqacc* acc) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_stream_frame   sf;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    if (request_stream_of(
            l, fr.type, wired_span_of(fr.start, fr.remaining), &sf)) {
      gather_one(&sf, acc);
      seen = 1;
    }
  return seen;
}

/* RFC 9000 2.2: the request is complete once FIN closed the stream and it has
 * not already been decoded/answered (curl FINs the request's last STREAM). */
/* Bytes of the complete HTTP/3 HEADERS frame at the head of acc, or 0 when
 * none is fully buffered yet (or the first frame is not HEADERS). */
static usz acc_headers_frame_len(const wired_srvloop_reqacc* acc) {
  quic_h3_frame f;
  usz           n = quic_h3_frame_get(wired_span_of(acc->buf, *acc->len), &f);
  if (n == 0) return 0;
  return f.type == QUIC_H3_FRAME_HEADERS ? n : 0;
}

/* Constant-shape 7-octet compare (the CONNECT method token). */
static int dispatch_bytes_eq7(const u8* m, const u8* want) {
  u8 d = 0;
  for (usz i = 0; i < 7; i++) d |= m[i] ^ want[i];
  return d == 0;
}

static int req_method_is_connect(const wired_h3reqdrive_req* r) {
  static const u8 want[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  if (!r->method || r->method_len != sizeof want) return 0;
  return dispatch_bytes_eq7(r->method, want);
}

/* Wrap acc's first n bytes as a STREAM frame in in->wrap (the same caller-
 * owned buffer drive_complete reuses right after) and decode the request
 * into *r. Returns 1 on a successful decode. */
static int peek_decode_request(
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in,
    usz                              n,
    wired_h3reqdrive_req*            r) {
  quic_stream_frame f  = {0, 0, n, acc->buf, 0};
  wired_obuf        ob = quic_obuf_of(in->wrap.p, in->wrap.n);
  if (!quic_appdata_stream_frame(&f, &ob)) return 0;
  return wired_h3reqdrive_recv_get(
      wired_span_of(in->wrap.p, ob.len), in->scratch, r);
}

/* RFC 9220 3 / draft-ietf-webtrans-http3 3: an Extended CONNECT's request
 * stream never carries FIN -- the stream IS the WebTransport session and
 * stays open for its whole lifetime -- so a CONNECT request is complete at
 * its HEADERS frame. 1 if acc currently holds one complete HEADERS frame
 * that decodes to a CONNECT request. */
static int connect_headers_complete(
    const wired_srvloop_reqacc* acc, const wired_srvloop_dispatch_in* in) {
  wired_h3reqdrive_req r;
  usz                  n = acc_headers_frame_len(acc);
  if (n == 0) return 0;
  if (!peek_decode_request(acc, in, n, &r)) return 0;
  return req_method_is_connect(&r);
}

/* A request is complete at FIN (RFC 9114 4.1) or, for a CONNECT, at its
 * complete HEADERS frame (see connect_headers_complete -- waiting for a FIN
 * that never comes starved every browser WebTransport session). */
static int request_complete(
    const wired_srvloop_reqacc* acc, const wired_srvloop_dispatch_in* in) {
  if (*acc->done) return 0;
  if (*acc->fin) return 1;
  return connect_headers_complete(acc, in);
}

/* 1 if the walked frame at `frame` is ANY client-bidi-id-shaped STREAM frame
 * (low bits 00) — the id space a WT bidi stream shares with request streams,
 * unlike request_stream_of this does NOT exclude a WT-signalled stream, since
 * this is exactly the classifier gather_wt_stream needs to find WT frames
 * request_stream_of deliberately skips. */
static int client_bidi_stream_of(
    u64 type, wired_span frame, quic_stream_frame* sf) {
  return is_stream(type) && quic_frame_get_stream(frame.p, frame.n, sf) &&
         is_request_stream(sf->stream_id);
}

/* RFC 9000 2.1: a server-initiated bidirectional stream has low bits 01 --
 * the client's reply half of a stream THIS endpoint opened
 * (wired_server_wt_open_bidi, srvrun.c). */
static int is_server_bidi_stream(u64 stream_id) {
  return (stream_id & 0x03) == 1;
}

/* 1 if the walked frame at `frame` belongs to a server-initiated bidi stream
 * (RFC 9000 2.1 id bits 01) -- the client-to-server reply half of a stream
 * srvrun.c itself opened (wired_server_wt_open_bidi). Mirrors
 * client_bidi_stream_of's shape for the separate id space. */
static int server_bidi_stream_of(
    u64 type, wired_span frame, quic_stream_frame* sf) {
  return is_stream(type) && quic_frame_get_stream(frame.p, frame.n, sf) &&
         is_server_bidi_stream(sf->stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: bytes of THIS frame's own data that are
 * the leading signal, not application data — slot->sig_len for the offset-0
 * signal frame itself (whose data begins with the signal varint, possibly
 * followed by application bytes that landed in the same frame), 0 for any
 * later frame (pure application data, the signal never reappears past
 * offset 0). */
static usz wt_frame_skip(
    const quic_stream_frame* sf, const wired_srvloop_wt_stream_slot* slot) {
  return sf->offset == 0 ? slot->sig_len : 0;
}

/* draft-ietf-webtrans-http3-15 4.3: land one WT bidi STREAM frame's
 * application bytes into slot->buf, honoring the slot's receive window (RFC
 * 9000 2.2's offset-indexed, reordering-tolerant reassembly — a frame may
 * arrive with a gap before it, or entirely re-cover already-delivered bytes).
 * `skip` is how many bytes of THIS frame's own data are the signal rather
 * than application data (nonzero only for the offset-0 frame, see
 * wt_frame_skip); `abs_off` is the frame's absolute post-signal stream
 * offset — every frame's stream-level offset is shifted left by the signal's
 * FULL encoded length (slot->sig_len), since the signal itself never
 * occupies any stream position, not just the offset-0 frame's own skip.
 * wired_srvloop_wt_window_accept answers where (and how much of) this lands
 * in slot->buf; bytes outside the currently open window are dropped (see its
 * own doc). */
static void gather_wt_one(
    const quic_stream_frame* sf, wired_srvloop_wt_stream_slot* slot) {
  usz skip    = wt_frame_skip(sf, slot);
  u64 abs_off = sf->offset - slot->sig_len + skip;
  usz n       = (usz)sf->length - skip;
  usz rel_off, accepted;
  wired_srvloop_wt_window_accept(&slot->win, abs_off, n, &rel_off, &accepted);
  if (accepted)
    quic_put_bytes(
        wired_mspan_of(slot->buf, sizeof slot->buf), &rel_off,
        wired_span_of(sf->data + skip + (n - accepted), accepted));
  if (sf->fin) {
    slot->fin     = 1;
    slot->fin_off = abs_off + n;
  }
}

/* draft-ietf-webtrans-http3-15 4.3: the leading signal on a WT bidi stream is
 * TWO varints -- the WT_STREAM type (0x41) and the session id (the CONNECT
 * stream's own id) -- so skipping only the type varint's length left the
 * session id's own bytes as a leading garbage byte on every request line
 * (found via a real webtransport-go interop run: the app's GET parser saw an
 * extra byte before "GET "). Consume both and sum their lengths. */
static usz wt_signal_len(wired_span data) {
  u64 v;
  usz off = 0;
  quic_varint_take(data, &off, &v);
  quic_varint_take(data, &off, &v);
  return off;
}

/* draft-ietf-webtrans-http3-15 4.3: find-or-claim the wt_streams slot for a
 * newly-signalled stream, recording the signal's own encoded length so
 * gather_wt_one can skip exactly that many bytes. Returns -1 (dropped, table
 * full) exactly like stream_slot_claim's fixed-capacity fallback. */
static int wt_slot_for_signal(wired_srvloop* l, const quic_stream_frame* sf) {
  int i = wired_srvloop_wt_slot_claim(l, sf->stream_id);
  if (i < 0) return -1;
  l->wt_streams[i].sig_len =
      wt_signal_len(wired_span_of(sf->data, (usz)sf->length));
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
static int gather_wt_frame(wired_srvloop* l, u64 type, wired_span frame) {
  quic_stream_frame sf;
  if (!client_bidi_stream_of(type, frame, &sf)) return 0;
  if (!wt_frame_relevant(l, &sf)) return 0;
  gather_wt_land(l, &sf);
  return 1;
}

/* draft-ietf-webtrans-http3-15 4.3: "Endpoints MUST NOT send WT_STREAM as a
 * frame type on HTTP/3 streams other than the very first bytes of a request
 * stream. Receiving this frame type in any other circumstances MUST be
 * treated as a connection error of type H3_FRAME_ERROR." sf's own leading
 * bytes decoding as the WT_STREAM signal at offset 0 is legitimate
 * (is_wt_stream_signal/sf_is_wt_signalled, checked and consumed elsewhere);
 * this is the SAME decode applied to a frame that is NOT at offset 0 -- the
 * one shape the RFC forbids outright. */
static int is_wt_signal_mid_stream(const quic_stream_frame* sf) {
  return sf->offset != 0 &&
         is_wt_stream_signal(wired_span_of(sf->data, (usz)sf->length));
}

/* 1 if the walked frame at `frame` is a client-bidi-id-shaped STREAM frame
 * (client_bidi_stream_of, the id space request/WT streams share) whose own
 * data decodes as the WT_STREAM signal at a non-zero offset
 * (is_wt_signal_mid_stream) -- latches l->wt_signal_mid_stream_violation,
 * mirroring gather_one_stream_close's latch-only shape. Scanned independent
 * of whether the same stream id was ALSO claimed as WT bidi traffic earlier
 * in this payload or an earlier step: draft-ietf-webtrans-http3-15 4.3 draws
 * no exception for an already-classified stream, and a legitimate WT bidi
 * continuation frame never itself re-decodes as the signal varint (the
 * signal is stripped from the stream's data by wt_frame_skip, never
 * repeated), so a real WT stream's own application bytes cannot spuriously
 * trigger this. */
static int gather_one_wt_signal_violation(
    wired_srvloop* l, u64 type, wired_span frame) {
  quic_stream_frame sf;
  if (!client_bidi_stream_of(type, frame, &sf)) return 0;
  if (!is_wt_signal_mid_stream(&sf)) return 0;
  l->wt_signal_mid_stream_violation = 1;
  return 1;
}

/* RFC 9000 2.1: land one server-initiated bidi stream's reply frame into its
 * pre-claimed wt_streams[] slot (wired_server_wt_open_bidi's own
 * wired_srvloop_wt_slot_claim_local call, srvrun.c). Unlike a client-signalled
 * WT stream, there is no signal varint to discover here -- a stream with no
 * slot yet is a frame for an id this endpoint never opened (or already
 * reaped), and is left alone rather than auto-claiming one, since only
 * srvrun.c (which alone knows the matching wired_wt_session) may open a slot
 * for this id space. Returns 1 iff frame belongs to this id space at all
 * (whether or not a slot existed to receive it), mirroring gather_wt_frame's
 * own seen semantics. */
static int gather_server_bidi_frame(
    wired_srvloop* l, u64 type, wired_span frame) {
  quic_stream_frame sf;
  int               i;
  if (!server_bidi_stream_of(type, frame, &sf)) return 0;
  i = wired_srvloop_wt_slot_find(l, sf.stream_id);
  if (i >= 0) gather_wt_one(&sf, &l->wt_streams[i]);
  return 1;
}

/* RFC 9000 2.2 / 12.4, draft-ietf-webtrans-http3-15 4.3: write every WT bidi
 * STREAM frame in this payload into its own wt_streams[] slot, at its offset
 * past the signal — independent of whether a request stream is ALSO present
 * in the same payload (a coalesced datagram may carry both). A stream is
 * recognized as WT bidi from its first (offset-0) signal frame; the slot is
 * claimed at that point. Also gathers a server-initiated bidi stream's client
 * reply (gather_server_bidi_frame), a disjoint id space (RFC 9000 2.1 bits 01
 * vs. 00) so a single pass over the payload's frames covers both. Returns 1
 * if any WT bidi frame (either id space) was seen. */
static int gather_wt_stream(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    seen |= gather_server_bidi_frame(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
    seen |= gather_wt_frame(l, fr.type, wired_span_of(fr.start, fr.remaining));
    seen |= gather_one_wt_signal_violation(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 2.1: a client-initiated unidirectional stream has low bits 10. */
static int is_uni_stream(u64 stream_id) { return (stream_id & 0x03) == 2; }

/* RFC 9114 6.2 / RFC 9204 4.2 / draft-ietf-webtrans-http3-15 4.3: peek (never
 * consumes/advances any state beyond this local decode) an uni stream's
 * offset-0 leading type varint and classify it via wired_h3srv_accept_uni —
 * the SAME classifier that already recognizes control (0x00) / QPACK
 * (0x02/0x03) / WebTransport (0x54), reused rather than reimplemented. An
 * undecodable leading varint classifies as not-accepted (0), same as any
 * other unrecognized type. */
static int uni_stream_type_accepted(wired_span data) {
  u64 v;
  usz off = 0;
  if (!quic_varint_take(data, &off, &v)) return 0;
  return wired_h3srv_accept_uni(v);
}

/* RFC 9204 4.2 (9204-028): if the leading type varint decodes to the QPACK
 * encoder or decoder stream type, record it on l's peer_qpack_* flags
 * (wired_h3srv_on_peer_qpack) -- a second instance of either type latches
 * l->qpack_stream_violation for the caller driving the loop to close the
 * connection over (H3_STREAM_CREATION_ERROR). Any other (or undecodable)
 * type is a no-op, matching uni_stream_type_accepted's own read-only peek. */
static void uni_stream_type_note_qpack(wired_srvloop* l, wired_span data) {
  u64 v;
  usz off = 0;
  u16 err;
  if (!quic_varint_take(data, &off, &v)) return;
  if (!wired_h3srv_on_peer_qpack(&l->h3, v, &err))
    l->qpack_stream_violation = err;
}

/* RFC 9204 4.3.1 (9204-020/9204-032/9204-033): if data's leading type varint
 * is the QPACK encoder stream, apply a Set Dynamic Table Capacity instruction
 * (if any) at its head to l->h3.qdyn. Other encoder-stream instructions
 * (Insert.../Duplicate) are left unconsumed -- see enc_stream.h's own doc for
 * why -- so this deliberately only tries the one instruction this SDK
 * decodes. A capacity exceeding the server's own advertised limit latches
 * l->qpack_stream_violation, mirroring uni_stream_type_note_qpack's shape. */
/* Apply a Set Dynamic Table Capacity instruction (if any) at the head of
 * rest to l, latching a rejection. Split out of uni_stream_type_apply_qpack_
 * capacity so its own branch count stays at the CCN gate. */
static void apply_qpack_capacity_rest(wired_srvloop* l, wired_span rest) {
  u16 err = 0;
  quic_qdyn_enc_apply_capacity(
      rest, &l->h3.qdyn, l->h3.qpack_max_table_capacity, &err);
  if (err) l->qpack_stream_violation = err;
}

static void uni_stream_type_apply_qpack_capacity(
    wired_srvloop* l, wired_span data) {
  u64 v;
  usz off = 0;
  if (!quic_varint_take(data, &off, &v)) return;
  if (v != QUIC_H3_STREAM_QPACK_ENCODER) return;
  apply_qpack_capacity_rest(l, wired_span_of(data.p + off, data.n - off));
}

/* draft-ietf-webtrans-http3-15 4.3: 1 if this uni stream's very first bytes
 * (an offset-0 STREAM frame's data) decode as the WT uni stream type varint
 * (0x54, RFC 9114 6.2/RFC 9220). Unlike a WT bidi stream's signal byte, a uni
 * stream's type is unambiguous and never mid-stream — only offset 0 is ever
 * checked, matching is_wt_stream_signal's own read-only peek (no state is
 * consumed beyond the local varint decode). */
static int is_wt_uni_stream_type(wired_span data) {
  u64 v;
  usz off = 0;
  if (!quic_varint_take(data, &off, &v)) return 0;
  return v == QUIC_H3_STREAM_WEBTRANSPORT;
}

/* 1 if sf is the stream's first-sighted (offset 0) frame and its leading
 * bytes decode as the WT uni stream type — the classification this slice adds
 * for a uni stream (mirrors sf_is_wt_signalled's bidi counterpart). */
static int sf_is_wt_uni_typed(const quic_stream_frame* sf) {
  return sf->offset == 0 &&
         is_wt_uni_stream_type(wired_span_of(sf->data, (usz)sf->length));
}

/* 1 if the walked frame at `frame` is a client uni STREAM frame (low bits 10)
 * — the id space wt_uni_streams draws from, decoded into sf for the caller. */
static int client_uni_stream_of(
    u64 type, wired_span frame, quic_stream_frame* sf) {
  return is_stream(type) && quic_frame_get_stream(frame.p, frame.n, sf) &&
         is_uni_stream(sf->stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: this uni frame is either the stream's
 * leading type byte (offset 0, decodes to 0x54) or belongs to a uni stream
 * already claimed in wt_uni_streams[] by an earlier typed frame. */
static int wt_uni_frame_relevant(
    const wired_srvloop* l, const quic_stream_frame* sf) {
  return sf_is_wt_uni_typed(sf) ||
         wired_srvloop_wt_uni_slot_find(l, sf->stream_id) >= 0;
}

/* Bytes of THIS uni frame's own data that are the leading type varint, not
 * application data — mirrors wt_frame_skip's bidi counterpart. */
static usz wt_uni_frame_skip(
    const quic_stream_frame* sf, const wired_srvloop_wt_uni_stream_slot* slot) {
  return sf->offset == 0 ? slot->type_len : 0;
}

/* draft-ietf-webtrans-http3-15 4.3: land one WT uni STREAM frame's application
 * bytes into slot->buf, mirroring gather_wt_one's bidi counterpart exactly
 * (skip the type varint's own bytes on the offset-0 frame, shift every
 * frame's offset back by the type varint's full encoded length, honor the
 * slot's receive window). */
static void gather_wt_uni_one(
    const quic_stream_frame* sf, wired_srvloop_wt_uni_stream_slot* slot) {
  usz skip    = wt_uni_frame_skip(sf, slot);
  u64 abs_off = sf->offset - slot->type_len + skip;
  usz n       = (usz)sf->length - skip;
  usz rel_off, accepted;
  wired_srvloop_wt_window_accept(&slot->win, abs_off, n, &rel_off, &accepted);
  if (accepted)
    quic_put_bytes(
        wired_mspan_of(slot->buf, sizeof slot->buf), &rel_off,
        wired_span_of(sf->data + skip + (n - accepted), accepted));
  if (sf->fin) {
    slot->fin     = 1;
    slot->fin_off = abs_off + n;
  }
}

/* draft-ietf-webtrans-http3-15 4.3: find-or-claim the wt_uni_streams slot for
 * a newly-typed stream, recording the leading signal's full encoded length
 * (type varint + session id varint, see wt_signal_len) so gather_wt_uni_one
 * can skip exactly that many bytes. */
static int wt_uni_slot_for_type(wired_srvloop* l, const quic_stream_frame* sf) {
  int i = wired_srvloop_wt_uni_slot_claim(l, sf->stream_id);
  if (i < 0) return -1;
  l->wt_uni_streams[i].type_len =
      wt_signal_len(wired_span_of(sf->data, (usz)sf->length));
  return i;
}

/* draft-ietf-webtrans-http3-15 4.3: the wt_uni_streams[] slot index for sf,
 * which wt_uni_frame_relevant already confirmed is WT uni traffic. */
static int wt_uni_slot_for(wired_srvloop* l, const quic_stream_frame* sf) {
  if (sf->offset == 0) return wt_uni_slot_for_type(l, sf);
  return wired_srvloop_wt_uni_slot_find(l, sf->stream_id);
}

/* qlog stream_frame_received (RFC 9000 19.8) for one WT uni STREAM frame
 * this connection's receive side just gathered, attributed via
 * l->qlog_path/qlog_group (srvrun_conn.qlog_slot's doc) -- the received-side
 * counterpart to srvrun_qlog_stream_sent. No-op without a qlog path. */
static void dispatch_qlog_stream_received(
    wired_srvloop* l, const quic_stream_frame* sf) {
  char                            rec[192];
  usz                             n;
  wired_qlogevent_stream_frame_in in;
  if (!l->qlog_path) return;
  in = (wired_qlogevent_stream_frame_in){
      sf->stream_id, sf->offset, sf->length, sf->fin, l->app_rx_pn};
  n = wired_qlogevent_stream_frame(
      rec, sizeof rec, l->now_ms, l->qlog_group, "stream_frame_received", &in);
  if (n) wired_qlog_append(l->qlog_path, wired_span_of((const u8*)rec, n));
}

/* draft-ietf-webtrans-http3-15 4.3: land sf (already confirmed WT uni
 * traffic) into its slot, claiming one on the leading type frame. */
static void gather_wt_uni_land(wired_srvloop* l, const quic_stream_frame* sf) {
  int i = wt_uni_slot_for(l, sf);
  if (i >= 0) gather_wt_uni_one(sf, &l->wt_uni_streams[i]);
  dispatch_qlog_stream_received(l, sf);
}

/* draft-ietf-webtrans-http3-15 4.3 / RFC 9114 6.2: classify a client uni
 * stream's leading type and gather it if (and only if) it is 0x54
 * (WebTransport). A recognized-but-not-WT type (control/QPACK,
 * wired_h3srv_accept_uni's existing classifier — reused rather than
 * reimplemented) or an unrecognized type is deliberately left untouched here:
 * has_stream/feed_or_accept's existing "STREAM frame present -> accepted,
 * content ignored" behavior already covers it unchanged, so this adds
 * classification without altering that path's outcome. */
/* Classify this uni stream's offset-0 leading type varint: a read-only peek
 * (wired_h3srv_accept_uni, its result unused here on purpose -- see
 * gather_wt_uni_frame's own doc) plus recording a QPACK encoder/decoder type
 * on l->h3.peer_qpack_* (RFC 9204 4.2, 9204-028). Split out of gather_wt_uni_
 * frame so its own branch count stays at the CCN gate. */
static void gather_wt_uni_classify(wired_srvloop* l, wired_span data) {
  uni_stream_type_accepted(data);
  uni_stream_type_note_qpack(l, data);
  uni_stream_type_apply_qpack_capacity(l, data);
}

static void gather_wt_uni_frame(wired_srvloop* l, const quic_stream_frame* sf) {
  wired_span data = wired_span_of(sf->data, (usz)sf->length);
  if (sf->offset == 0) gather_wt_uni_classify(l, data);
  if (!wt_uni_frame_relevant(l, sf)) return;
  gather_wt_uni_land(l, sf);
}

/* 1 if the walked frame at `frame` is a client uni STREAM frame whose leading
 * (or already-claimed) type classifies as WebTransport (0x54); gathers it into
 * wt_uni_streams[] when so. Returns 1 iff this frame belonged to a uni stream
 * at all (matching gather_wt_frame's "seen" semantics for the bidi table) —
 * this lets the caller keep such a payload out of dispatch_non_request's
 * handshake-feed fallback exactly like a bidi/request STREAM frame does. */
static int gather_uni_frame(wired_srvloop* l, u64 type, wired_span frame) {
  quic_stream_frame sf;
  if (!client_uni_stream_of(type, frame, &sf)) return 0;
  gather_wt_uni_frame(l, &sf);
  return 1;
}

/* RFC 9000 2.2 / 12.4, draft-ietf-webtrans-http3-15 4.3: write every client
 * uni STREAM frame's WT-typed (0x54) bytes into its own wt_uni_streams[] slot,
 * at its offset past the type varint; a control/QPACK/unrecognized-typed uni
 * stream frame is classified (client_uni_stream_of matches) but left
 * otherwise untouched (gather_wt_uni_frame's no-op path). Returns 1 if any uni
 * STREAM frame was seen this payload, independent of its type. */
static int gather_uni_stream(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    seen |= gather_uni_frame(l, fr.type, wired_span_of(fr.start, fr.remaining));
  return seen;
}

/* RFC 9218 7.1 / 10, RFC 9114 6.2.1: reassemble every client uni STREAM frame
 * belonging to the peer's control stream into l->ctrl and apply any newly
 * complete PRIORITY_UPDATE frame (wired_srvloop_ctrl_gather), mirroring
 * gather_uni_stream's own walk shape. Returns 1 if any control-stream frame
 * was seen this payload. */
static int gather_ctrl_priupdate(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    seen |= wired_srvloop_ctrl_gather(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  return seen;
}

/* RFC 9218 7.1 / 9218-013: scan every client bidi (request) STREAM frame this
 * payload carries for a PRIORITY_UPDATE frame, latching l->priupdate_
 * violation on one (wired_srvloop_req_priupdate_gather), mirroring
 * gather_ctrl_priupdate's own walk shape. Returns 1 if any request-stream
 * frame was seen this payload. */
static int gather_req_priupdate(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr))
    seen |= wired_srvloop_req_priupdate_gather(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  return seen;
}

/* RFC 9221 5: copy one decoded DATAGRAM frame's payload into the next free
 * rx_datagrams slot (truncated to its cap, matching this repo's existing
 * truncate-on-overflow policy for fixed buffers). Caller has already checked
 * the queue is not full. */
static void queue_rx_datagram(wired_srvloop* l, wired_span payload) {
  wired_srvloop_rx_datagram* slot = &l->rx_datagrams[l->rx_datagram_n];
  usz                        cap  = sizeof slot->buf;
  usz                        n    = payload.n < cap ? payload.n : cap;
  usz                        off  = 0;
  quic_put_bytes(
      wired_mspan_of(slot->buf, cap), &off, wired_span_of(payload.p, n));
  slot->len = n;
  l->rx_datagram_n++;
}

/* RFC 9221 3: this connection's own advertised max_datagram_frame_size (0 =
 * never advertised, this repo's existing sentinel) authorizes payload as a
 * DATAGRAM the peer had a right to send. Delegates to the pre-existing
 * predicate (dgcheck.h); the "we advertised at all" flag is derived here from
 * the 0-sentinel rather than threaded as a separate bit. */
static int datagram_size_ok(const wired_srvloop* l, usz payload_len) {
  return quic_datagram_recv_ok(
      l->we_advertised_max_datagram, l->we_advertised_max_datagram > 0,
      (u64)payload_len);
}

/* Decode frame's DATAGRAM payload and either queue it (RFC 9221 3 size check
 * passes) or latch l->datagram_violation for the caller to close the
 * connection over (RFC 9221 3: PROTOCOL_VIOLATION). A malformed frame queues
 * nothing and is not itself a violation (distinct failure mode). Caller
 * (gather_one_datagram) has already confirmed the type and queue room. */
static void queue_decoded_datagram(wired_srvloop* l, wired_span frame) {
  wired_span payload;
  if (!quic_dgdeliver_extract(frame, &payload)) return;
  if (!datagram_size_ok(l, payload.n)) {
    l->datagram_violation = 1;
    return;
  }
  queue_rx_datagram(l, payload);
}

/* RFC 9221 5: if the walked frame of `type` at `frame` is a DATAGRAM and the
 * queue has room, decode its payload and queue it (or latch a violation, see
 * queue_decoded_datagram). A full queue drops the newly arrived datagram (see
 * rx_datagram_n's doc for why): RFC 9221 datagrams are unreliable, so silently
 * dropping one under sustained load is within spec rather than a bug to fix.
 */
static void gather_one_datagram(wired_srvloop* l, u64 type, wired_span frame) {
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
    gather_one_datagram(l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.4: extract the stream id RESET_STREAM (0x04) closed, 0 if frame
 * is not a RESET_STREAM or fails to decode. draft-ietf-quic-reliable-stream-
 * reset's RESET_STREAM_AT (0x24) is deliberately excluded here: it declares a
 * RELIABLE size and is not itself the close signal this loop tracks
 * (srvrun.c does not yet emit it so there is no live peer path to test
 * against). */
static int reset_stream_id(u64 type, wired_span frame, u64* stream_id_out) {
  quic_reset_stream_frame f;
  if (quic_frame_classify(type) != QUIC_FK_RESET_STREAM) return 0;
  if (quic_reset_stream_decode(frame.p, frame.n, &f) == 0) return 0;
  *stream_id_out = f.stream_id;
  return 1;
}

/* RFC 9000 19.5: extract the stream id STOP_SENDING (0x05) named, 0 if frame
 * is not a STOP_SENDING or fails to decode. STOP_SENDING is the peer telling
 * US to stop sending on stream_id — recorded the same as a RESET_STREAM
 * closing it, since either end of a bidi stream that will never carry more
 * data again is the observable "this stream is done" signal this loop
 * tracks. */
static int stop_sending_id(u64 type, wired_span frame, u64* stream_id_out) {
  quic_stop_sending_frame f;
  if (quic_frame_classify(type) != QUIC_FK_STOP_SENDING) return 0;
  if (quic_stop_sending_decode(frame.p, frame.n, &f) == 0) return 0;
  *stream_id_out = f.stream_id;
  return 1;
}

/* RFC 9000 19.4: 1 if frame is a RESET_STREAM, its stream_id/error_code
 * decoded into *out. Split out of gather_one_wt_reset to keep its own branch
 * count at the CCN gate. */
static int wt_reset_frame(
    u64 type, wired_span frame, quic_reset_stream_frame* out) {
  if (quic_frame_classify(type) != QUIC_FK_RESET_STREAM) return 0;
  return quic_reset_stream_decode(frame.p, frame.n, out) != 0;
}

/* RFC 9000 19.5: 1 if frame is a STOP_SENDING, its stream_id/error_code
 * decoded into *out. Mirrors wt_reset_frame for the other close-shaped
 * frame kind. */
static int wt_stop_frame(
    u64 type, wired_span frame, quic_stop_sending_frame* out) {
  if (quic_frame_classify(type) != QUIC_FK_STOP_SENDING) return 0;
  return quic_stop_sending_decode(frame.p, frame.n, out) != 0;
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-040): if the walked frame at
 * `frame` is a RESET_STREAM or STOP_SENDING, latch its (stream_id,
 * error_code) into l->wt_reset_*, mirroring gather_one_stream_close's own
 * latch-only shape but ALSO keeping the wire error code
 * (reset_stream_id/stop_sending_id both discard it, since the CONNECT-
 * stream-close case they serve never needed it). l has no notion of which
 * stream id belongs to a WT session -- the caller (srvrun.c) resolves that
 * and decides whether/how to map the code through wired_wterrmap_from_http3.
 * Only the last one seen this step survives if more than one arrives, same
 * convention as closed_stream_id. */
static void gather_one_wt_reset(wired_srvloop* l, u64 type, wired_span frame) {
  quic_reset_stream_frame rs;
  quic_stop_sending_frame ss;
  if (wt_reset_frame(type, frame, &rs)) {
    l->wt_reset_stream_id  = rs.stream_id;
    l->wt_reset_error_code = rs.error_code;
    l->wt_reset_is_stop    = 0;
    l->wt_reset_seen       = 1;
    return;
  }
  if (!wt_stop_frame(type, frame, &ss)) return;
  l->wt_reset_stream_id  = ss.stream_id;
  l->wt_reset_error_code = ss.error_code;
  l->wt_reset_is_stop    = 1;
  l->wt_reset_seen       = 1;
}

/* RFC 9000 19.8: 1 if frame is a client bidi STREAM frame with FIN set,
 * *stream_id_out set to its id — a client-initiated bidi stream (e.g. a
 * WebTransport CONNECT stream, draft-ietf-webtrans-http3-15 SS4.4) ending its
 * client-to-server half. Reuses client_bidi_stream_of's own id-space check
 * rather than is_request_stream directly, so a stream already claimed by
 * wt_streams[] (checked elsewhere, not here) is not excluded: closing is
 * tracked independent of which path is reassembling the stream's bytes. */
static int stream_fin_id(u64 type, wired_span frame, u64* stream_id_out) {
  quic_stream_frame sf;
  if (!client_bidi_stream_of(type, frame, &sf) || !sf.fin) return 0;
  *stream_id_out = sf.stream_id;
  return 1;
}

/* RFC 9000 19.4/19.5/19.8: the stream id `frame` (of `type`) closes, via
 * whichever of the three close-shaped decoders recognizes it; 0 if frame is
 * none of them. Split from gather_one_stream_close to keep its own branch
 * count at the CCN gate. */
static int closed_frame_id(u64 type, wired_span frame, u64* stream_id_out) {
  if (reset_stream_id(type, frame, stream_id_out)) return 1;
  if (stop_sending_id(type, frame, stream_id_out)) return 1;
  return stream_fin_id(type, frame, stream_id_out);
}

/* RFC 9000 19.4/19.5/19.8: if the walked frame at `frame` closes a stream
 * (closed_frame_id), latch its id into l->closed_stream_id — a peer ending
 * its side of a bidi stream (e.g. the CONNECT stream of a WebTransport
 * session, draft-ietf-webtrans-http3-15 SS4.4) independent of the rest of the
 * connection. l has no notion of what stream_id belongs to; the caller
 * driving the loop (srvrun.c) decides what a closed id means. Only the last
 * one seen this step survives if more than one arrives (mirrors got_request's
 * own "last one wins" mirroring), which is enough for the single-CONNECT-
 * stream-per-connection shape this SDK serves. */
static void gather_one_stream_close(
    wired_srvloop* l, u64 type, wired_span frame) {
  u64 stream_id;
  if (!closed_frame_id(type, frame, &stream_id)) return;
  l->closed_stream_id   = stream_id;
  l->closed_stream_seen = 1;
}

/* 1 if kind is one of the close-shaped frame kinds gather_stream_closes scans
 * for (RESET_STREAM/STOP_SENDING/any STREAM, the latter since a FIN-bearing
 * one is only distinguishable after decoding). Split out to keep
 * gather_stream_closes' own branch count at the CCN gate. */
static int is_close_shaped(quic_frame_kind kind, u64 type) {
  return kind == QUIC_FK_RESET_STREAM || kind == QUIC_FK_STOP_SENDING ||
         is_stream(type);
}

/* 1 if candidate should replace l->max_data_seen: either nothing latched
 * yet this step, or candidate is the higher of the two seen so far -- split
 * out so gather_one_max_data's own CCN stays at the gate (a compound `||`
 * counts as +1 on top of its enclosing if). */
static int max_data_is_new_high(const wired_srvloop* l, u64 candidate) {
  return !l->max_data_seen_flag || candidate > l->max_data_seen;
}

/* RFC 9000 19.9: latch the highest MAX_DATA value seen in this payload --
 * only ever raised by the caller (srvrun.c), never applied here, since RFC
 * 9000 4.1 forbids a send credit from ever decreasing and this loop has no
 * notion of the running credit to compare against. Caller (gather_max_data)
 * has already confirmed frame's kind, so this only decodes. */
static void gather_one_max_data(wired_srvloop* l, wired_span frame) {
  quic_data_frame f;
  if (quic_max_data_decode(frame.p, frame.n, &f) == 0) return;
  if (max_data_is_new_high(l, f.value)) l->max_data_seen = f.value;
  l->max_data_seen_flag = 1;
}

/* RFC 9000 19.11: latch one MAX_STREAMS(uni) frame's value as a running
 * high-water mark (a lower/equal value never lowers it -- limits only ever
 * grow, mirroring max_data_is_new_high). Bidi MAX_STREAMS is ignored here:
 * this server opens no bidi streams the peer's bidi limit would gate except
 * the per-session WT control replies, whose ids the client itself opened. */
/* 1 iff a decoded MAX_STREAMS frame raises the step's uni high-water mark:
 * uni direction only, and only an actual raise (limits never decrease). */
static int max_streams_uni_is_new_high(
    const wired_srvloop* l, int uni, u64 max) {
  return uni && max > l->max_streams_uni_seen;
}

static void gather_one_max_streams_uni(wired_srvloop* l, wired_span frame) {
  int uni;
  u64 max;
  if (!quic_maxstreams_parse(frame, &uni, &max)) return;
  if (!max_streams_uni_is_new_high(l, uni, max)) return;
  l->max_streams_uni_seen      = max;
  l->max_streams_uni_seen_flag = 1;
}

/* RFC 9000 19.11: scan this payload for MAX_STREAMS frames, mirroring
 * gather_max_data's shape. Returns 1 if any was seen. */
static int gather_max_streams_uni(
    wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (quic_frame_classify(fr.type) != QUIC_FK_MAX_STREAMS) continue;
    seen = 1;
    gather_one_max_streams_uni(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.14: latch which STREAMS_BLOCKED direction was seen -- the two
 * directions carry independent limits, so each gets its own flag. */
static void note_streams_blocked(wired_srvloop* l, u64 type) {
  if (type == QUIC_FRAME_STREAMS_BLOCKED_BIDI) l->streams_blocked_seen_flag = 1;
  if (type == QUIC_FRAME_STREAMS_BLOCKED_UNI)
    l->streams_blocked_uni_seen_flag = 1;
}

/* RFC 9000 19.14: scan this payload for a STREAMS_BLOCKED frame (either
 * direction), mirroring gather_max_data's shape. Only the frame's presence
 * matters (srvrun.c computes the re-grant from its own slot state, not the
 * peer's claimed limit -- see streams_blocked_seen_flag's doc), so this just
 * sets the direction's flag rather than decoding a value. Returns 1 if one
 * was seen. */
static int gather_streams_blocked(
    wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (quic_frame_classify(fr.type) != QUIC_FK_STREAMS_BLOCKED) continue;
    seen = 1;
    note_streams_blocked(l, fr.type);
  }
  return seen;
}

/* Decode one PATH_RESPONSE frame into l's latch, mirroring
 * gather_one_max_data's split (loop body pulled out to keep the scanning
 * loop's own CCN at the gate). A malformed/truncated frame is silently
 * skipped, same policy as gather_one_max_data's decode failure. */
static void gather_one_path_response(wired_srvloop* l, wired_span frame) {
  if (!quic_path_decode(
          frame.p, frame.n, QUIC_FRAME_PATH_RESPONSE, l->path_response_data))
    return;
  l->path_response_seen_flag = 1;
}

/* RFC 9000 8.2.2/19.18: scan this payload for a PATH_RESPONSE frame,
 * mirroring gather_max_data's shape (latch presence + one fixed-size value,
 * no running-high-water-mark comparison needed). A payload carrying more
 * than one PATH_RESPONSE this step is not expected in practice (this server
 * only ever has one challenge outstanding, srvrun_conn.migrate), so only the
 * last one seen is kept -- exactly gather_one_max_data's own
 * last-in-step-among-several convention for a single-slot latch. */
static int gather_path_response(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (quic_frame_classify(fr.type) != QUIC_FK_PATH_RESPONSE) continue;
    seen = 1;
    gather_one_path_response(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.9: scan this payload for MAX_DATA frames, mirroring
 * gather_stream_closes' shape for a different frame kind. Returns 1 if any
 * was seen. */
static int gather_max_data(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (quic_frame_classify(fr.type) != QUIC_FK_MAX_DATA) continue;
    seen = 1;
    gather_one_max_data(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* Index of stream_id's existing slot in l's this-step MAX_STREAM_DATA
 * latch, or -1 if it has none yet. */
static int max_stream_data_slot_for(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < l->max_stream_data_n; i++)
    if (l->max_stream_data_stream_id[i] == stream_id) return (int)i;
  return -1;
}

/* RFC 9000 19.10: latch (stream_id, value) into its own slot -- a repeat
 * stream_id this step overwrites its existing slot (only the newest value
 * for a given stream matters); a new one takes the next free slot, silently
 * dropped if every slot is already used (WIRED_SRVLOOP_MAX_STREAMS already
 * bounds how many distinct request streams this connection reassembles at
 * once, so more distinct MAX_STREAM_DATA targets than that in one step
 * cannot happen). The caller (srvrun.c) resolves which resp[] slot each
 * stream_id belongs to and raises that slot's own running credit, never
 * lowering it (RFC 9000 4.1). */
/* stream_id's slot: its existing one (max_stream_data_slot_for), else a
 * freshly claimed one, else -1 once every slot is already used. */
static int max_stream_data_slot(wired_srvloop* l, u64 stream_id) {
  int i = max_stream_data_slot_for(l, stream_id);
  if (i >= 0) return i;
  if (l->max_stream_data_n >= WIRED_SRVLOOP_MAX_STREAMS) return -1;
  i                               = (int)l->max_stream_data_n++;
  l->max_stream_data_stream_id[i] = stream_id;
  return i;
}

static void gather_one_max_stream_data(wired_srvloop* l, wired_span frame) {
  quic_stream_data_frame f;
  int                    i;
  if (quic_max_stream_data_decode(frame.p, frame.n, &f) == 0) return;
  i = max_stream_data_slot(l, f.stream_id);
  if (i >= 0) l->max_stream_data_value[i] = f.value;
}

/* RFC 9000 19.10: scan this payload for MAX_STREAM_DATA frames. Returns 1 if
 * any was seen. */
static int gather_max_stream_data(
    wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (quic_frame_classify(fr.type) != QUIC_FK_MAX_STREAM_DATA) continue;
    seen = 1;
    gather_one_max_stream_data(l, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 19.4/19.5/19.8: scan this payload for RESET_STREAM/STOP_SENDING/
 * FIN-bearing STREAM frames, mirroring gather_rx_datagrams' shape for a
 * different frame kind set. Returns 1 if any was seen this payload (whether
 * or not it was the last one latched); this deliberately does NOT gate
 * dispatch_non_request's handshake-feed fallback the way gather_request/
 * gather_wt_stream/gather_rx_datagrams do, since a FIN-bearing STREAM frame
 * is already a STREAM frame those paths (or has_stream's own check) already
 * account for. */
static int gather_stream_closes(wired_srvloop* l, const u8* payload, usz len) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_framewalk_init(&it, payload, len);
  while (quic_framewalk_next(&it, &fr)) {
    if (is_close_shaped(quic_frame_classify(fr.type), fr.type)) seen = 1;
    gather_one_stream_close(l, fr.type, wired_span_of(fr.start, fr.remaining));
    gather_one_wt_reset(l, fr.type, wired_span_of(fr.start, fr.remaining));
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
  wired_obuf        ob = quic_obuf_of(in->wrap.p, in->wrap.n);
  *acc->done           = 1;
  if (quic_appdata_stream_frame(&f, &ob))
    dispatch_stream(h3, wired_span_of(in->wrap.p, ob.len), in);
}

/* quic-interop-runner's hq-interop (HTTP/0.9 over QUIC, see hq09.h):
 * parse acc's reassembled bytes as a single "GET <path>\r\n" request line
 * (no QPACK/HEADERS framing at all -- the accumulated bytes ARE the
 * request line). On a valid line, sets *in->req's path (a view into acc's
 * own storage, which outlives this call the same way in->wrap does for the
 * H3 path) and marks the request complete; an invalid line marks acc done
 * without producing a request (the stream is spent either way, matching
 * drive_complete's "decode at most once" contract). */
static void drive_complete_hq09(
    wired_srvloop_reqacc* acc, const wired_srvloop_dispatch_in* in) {
  wired_span path;
  *acc->done = 1;
  if (!wired_hq09_parse_get(wired_span_of(acc->buf, *acc->len), &path)) return;
  *in->req            = (wired_h3reqdrive_req){0};
  in->req->method     = (const u8*)"GET";
  in->req->method_len = 3;
  in->req->path       = path.p;
  in->req->path_len   = path.n;
  *in->got_request    = 1;
}

/* RFC 9000 2.2: view one stream slot's cross-datagram request accumulator
 * (the routed path's per-slot counterpart of the caller-built ctx->acc). */
static wired_srvloop_reqacc route_slot_acc(wired_srvloop_stream_slot* slot) {
  wired_srvloop_reqacc acc;
  acc.buf  = slot->req_buf;
  acc.cap  = sizeof slot->req_buf;
  acc.len  = &slot->req_len;
  acc.fin  = &slot->req_fin;
  acc.done = &slot->req_done;
  return acc;
}

/* Land one request STREAM frame in its own stream's slot (claiming one on
 * first sight) and mark that slot touched. A full table drops the frame --
 * same policy as the old single fixed slot. */
static void route_land(
    wired_srvloop* l, const quic_stream_frame* sf, u64* touched) {
  int                  i = wired_srvloop_slot_for(l, sf->stream_id);
  wired_srvloop_reqacc acc;
  /* RFC 9000 3.2: a late duplicate of an answered-and-released stream is
   * discarded outright -- it must not consume a slot or count as new. */
  if (i == -2) return;
  if (i < 0) return;
  acc = route_slot_acc(&l->streams[i]);
  gather_one(sf, &acc);
  /* u64: the table holds up to WIRED_SRVLOOP_MAX_STREAMS (40) slots, so a
   * 32-bit mask loses (as undefined-behavior shifts) slots 32..39. */
  *touched |= (u64)1 << i;
}

/* RFC 9000 2.2 / 12.4: route every request STREAM frame in this payload to
 * its own stream's slot (a payload may coalesce frames of several request
 * streams -- quic-go packs parallel GETs' HEADERS into one packet). Returns
 * 1 if any request-stream frame was seen, with *touched marking the slots
 * written. */
static int route_request_frames(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload, u64* touched) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 seen = 0;
  quic_stream_frame   sf;
  quic_framewalk_init(&it, payload.p, payload.n);
  while (quic_framewalk_next(&it, &fr))
    if (request_stream_of(
            ctx->l, fr.type, wired_span_of(fr.start, fr.remaining), &sf)) {
      route_land(ctx->l, &sf, touched);
      seen = 1;
    }
  return seen;
}

/* Append slot i to this step's completion list and mirror its request into
 * l->req/req_stream_id (the pre-existing single-request API surface; the
 * mirror carries the LAST completion when more than one lands this step). */
static void route_note_done(wired_srvloop* l, int i) {
  l->req           = l->streams[i].req;
  l->req_stream_id = l->streams[i].stream_id;
  if (l->done_n < WIRED_SRVLOOP_MAX_STREAMS) l->done_slots[l->done_n++] = (u8)i;
}

/* Append slot i to frame_unexpected_slots (RFC 9114 7.2.5/7.2.8, 9114-067/
 * 9114-073) -- split out of route_note_incomplete so its own reject-vs-
 * incomplete branch stays a single extra check there. */
static void route_note_frame_unexpected(wired_srvloop* l, int i) {
  if (l->frame_unexpected_n < WIRED_SRVLOOP_MAX_STREAMS)
    l->frame_unexpected_slots[l->frame_unexpected_n++] = (u8)i;
}

/* Mark slot i incomplete and append it to incomplete_slots -- the actual
 * H3_REQUEST_INCOMPLETE bookkeeping, split out of route_note_incomplete so
 * its own reject-vs-incomplete branch stays a single extra check there. */
static void route_note_incomplete_append(wired_srvloop* l, int i) {
  l->streams[i].req_incomplete = 1;
  if (l->incomplete_n < WIRED_SRVLOOP_MAX_STREAMS)
    l->incomplete_slots[l->incomplete_n++] = (u8)i;
}

/* RFC 9114 4.1: slot i's request stream reached FIN without decoding into a
 * request -- append it to incomplete_slots (the H3_REQUEST_INCOMPLETE
 * counterpart of route_note_done) for whichever layer aborts it, UNLESS the
 * decode failed because the stream carried a frame this endpoint must reject
 * outright (req.frame_unexpected, 9114-067/9114-073), which takes the
 * H3_FRAME_UNEXPECTED list instead. A CONNECT completed by
 * connect_headers_complete rather than FIN is never incomplete (it
 * deliberately never gets a FIN, see request_complete's doc), so this is
 * gated on the stream's own FIN latch, not just "decode failed". */
static void route_note_incomplete(wired_srvloop* l, int i) {
  wired_srvloop_stream_slot* slot = &l->streams[i];
  if (!slot->req_fin) return;
  if (slot->req.frame_unexpected)
    route_note_frame_unexpected(l, i);
  else
    route_note_incomplete_append(l, i);
}

/* RFC 9114 4.1 vs hq-interop (see hq09.h): dispatch slot i's just-completed
 * request through whichever decoder this connection negotiated -- QPACK/
 * HEADERS for h3, a bare "GET <path>\r\n" line for hq-interop. Split out so
 * route_complete_slot's own CCN stays at the gate. */
static void route_dispatch_complete(
    const wired_srvloop_dispatch_ctx* ctx,
    wired_srvloop_reqacc*             acc,
    const wired_srvloop_dispatch_in*  sin) {
  if (ctx->s->sdrv.alpn == QUIC_SALPN_HQ)
    drive_complete_hq09(acc, sin);
  else
    drive_complete(ctx->h3, acc, sin);
}

/* Decode slot i's request if it just completed, using the slot's OWN
 * scratch/wrap/req storage (each stream's decoded views must stay alive
 * independently of the others'). */
static void route_complete_slot(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in,
    int                               i) {
  wired_srvloop_stream_slot* slot = &ctx->l->streams[i];
  wired_srvloop_reqacc       acc  = route_slot_acc(slot);
  int                        got  = 0;
  wired_srvloop_dispatch_in  sin  = {
      in->payload, wired_mspan_of(slot->req_scratch, sizeof slot->req_scratch),
      wired_mspan_of(slot->req_wrap, sizeof slot->req_wrap), &got, &slot->req};
  if (!request_complete(&acc, &sin)) return;
  route_dispatch_complete(ctx, &acc, &sin);
  if (got)
    route_note_done(ctx->l, i);
  else
    route_note_incomplete(ctx->l, i);
}

/* Run completion over every slot this payload touched. */
static void route_complete_touched(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in,
    u64                               touched) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if ((touched >> i) & (u64)1) route_complete_slot(ctx, in, (int)i);
}

/* The routed (ctx->l != 0) reassembly path: per-frame slot routing, then
 * per-touched-slot completion. */
static int reassemble_routed(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  u64 touched = 0;
  if (!route_request_frames(ctx, in->payload, &touched)) return 0;
  route_complete_touched(ctx, in, touched);
  return 1;
}

/* The single-accumulator (ctx->l == 0) path: the caller owns the acc and the
 * scratch/wrap/req in `in` -- the direct-dispatch test surface. */
static int reassemble_single(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  if (!gather_request(ctx->l, in->payload.p, in->payload.n, ctx->acc)) return 0;
  if (request_complete(ctx->acc, in)) drive_complete(ctx->h3, ctx->acc, in);
  return 1;
}

/* RFC 9000 2.2 / RFC 9114 4.1: accumulate this payload's request-stream frames;
 * once FIN closes the stream, decode the reassembled request exactly once.
 * Returns 1 if a request-stream frame was present (handled), 0 otherwise. */
static int reassemble_and_drive(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  return ctx->l ? reassemble_routed(ctx, in) : reassemble_single(ctx, in);
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
static int dispatch_gather_wt(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) return 0;
  return gather_wt_stream(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to queue DATAGRAM frames into (ctx->l != 0) and this
 * payload carried any (RFC 9221 5). A dispatch caller exercising only the
 * request path directly (l == 0) skips DATAGRAM gathering entirely rather
 * than dereferencing a null loop. */
static int dispatch_gather_datagrams(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) return 0;
  return gather_rx_datagrams(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to gather uni stream traffic into (ctx->l != 0) and this
 * payload carried any client uni STREAM frame (draft-ietf-webtrans-http3-15
 * 4.3 / RFC 9114 6.2), mirroring dispatch_gather_wt for the uni table. */
static int dispatch_gather_uni(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) return 0;
  return gather_uni_stream(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to latch a closed stream id into (ctx->l != 0) and this
 * payload carried a RESET_STREAM/STOP_SENDING/FIN-bearing STREAM frame
 * (RFC 9000 19.4/19.5/19.8), mirroring dispatch_gather_wt for
 * gather_stream_closes. A payload carrying only RESET_STREAM/STOP_SENDING
 * (neither of which has_stream's STREAM-only check recognizes) would
 * otherwise fall through to dispatch_non_request's handshake-feed fallback
 * (RFC 9000 12.4: a 1-RTT payload must never re-enter the handshake). */
static int dispatch_gather_closes(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) return 0;
  return gather_stream_closes(ctx->l, payload.p, payload.n);
}

/* RFC 9000 19.9/19.10: 1 if ctx has a loop to latch a flow-control update
 * into and this payload carried a MAX_DATA or MAX_STREAM_DATA frame,
 * mirroring dispatch_gather_closes for the flow-control frame kinds. */
static int dispatch_gather_flowctl(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  int got_max_data, got_max_stream_data, got_max_streams, got_streams_blocked,
      got_path_resp;
  if (!ctx->l) return 0;
  got_max_data        = gather_max_data(ctx->l, payload.p, payload.n);
  got_max_stream_data = gather_max_stream_data(ctx->l, payload.p, payload.n);
  got_max_streams     = gather_max_streams_uni(ctx->l, payload.p, payload.n);
  got_streams_blocked = gather_streams_blocked(ctx->l, payload.p, payload.n);
  got_path_resp       = gather_path_response(ctx->l, payload.p, payload.n);
  return got_max_data | got_max_stream_data | got_max_streams |
         got_streams_blocked | got_path_resp;
}

/* RFC 9218 7.1 / 10: 1 if ctx has a loop to reassemble the peer's control
 * stream into (ctx->l != 0) and this payload carried any of its frames,
 * mirroring dispatch_gather_uni for the PRIORITY_UPDATE-applying walk. */
static int dispatch_gather_ctrl_priupdate(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) return 0;
  return gather_ctrl_priupdate(ctx->l, payload.p, payload.n);
}

/* RFC 9218 7.1 / 9218-013: 1 if ctx has a loop to latch a PRIORITY_UPDATE
 * violation into (ctx->l != 0) and this payload carried a request-stream
 * frame, mirroring dispatch_gather_ctrl_priupdate for the request-side scan.
 */
static int dispatch_gather_req_priupdate(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) return 0;
  return gather_req_priupdate(ctx->l, payload.p, payload.n);
}

/* RFC 9000 12.4 / 2.1, RFC 9114 6.2: a payload may lead with PADDING/ACK before
 * its CRYPTO or STREAM frame (curl/quiche do this). A client bidi STREAM drives
 * HTTP/3; unidirectional STREAMs are accepted but ignored; anything else is
 * handed whole to wired_server_feed, whose crecv reassembles a split
 * ClientHello/Finished. A STREAM payload never re-enters the handshake, and
 * neither does a WT bidi stream (draft-ietf-webtrans-http3-15 4.3), a client
 * uni stream (control/QPACK/WebTransport, same draft/RFC 9114 6.2), or a
 * DATAGRAM frame (RFC 9221 5) — all three are gathered independently before
 * either path below, since a coalesced payload may carry any combination. */
/* Gather this payload's WT bidi, uni, DATAGRAM, stream-close, and
 * PRIORITY_UPDATE-relevant frames (each independent of the others, see
 * wired_srvloop_dispatch's doc); 1 if any kind was present. */
static int dispatch_gather_side_channels(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  int got_wt       = dispatch_gather_wt(ctx, payload);
  int got_uni      = dispatch_gather_uni(ctx, payload);
  int got_dg       = dispatch_gather_datagrams(ctx, payload);
  int got_closes   = dispatch_gather_closes(ctx, payload);
  int got_flowctl  = dispatch_gather_flowctl(ctx, payload);
  int got_ctrl_pri = dispatch_gather_ctrl_priupdate(ctx, payload);
  int got_req_pri  = dispatch_gather_req_priupdate(ctx, payload);
  return got_wt | got_uni | got_dg | got_closes | got_flowctl | got_ctrl_pri |
         got_req_pri;
}

int wired_srvloop_dispatch(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  int handled_side = dispatch_gather_side_channels(ctx, in->payload);
  if (reassemble_and_drive(ctx, in)) return 1;
  if (handled_side) return 1;
  return dispatch_non_request(ctx->s, in->payload.p, in->payload.n);
}
