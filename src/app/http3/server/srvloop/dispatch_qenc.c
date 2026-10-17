#include "app/http3/server/srvloop/dispatch_impl.h"

static void gather_wt_land(wired_srvloop* l, const stream_frame* sf);
static int  is_wt_signal_mid_stream(const stream_frame* sf);
static int  gather_one_wt_signal_violation(
    wired_srvloop* l, u64 type, wired_span frame);
static int qenc_type_is_encoder(const stream_frame* sf);
static int qenc_leads_encoder(const wired_srvloop* l, const stream_frame* sf);
static int qenc_frame_untyped(const stream_frame* sf);
static int qenc_type_known(const wired_srvloop* l, const stream_frame* sf);
static int qenc_stream_known(const wired_srvloop* l, const stream_frame* sf);
static int qenc_window_free(const wired_srvloop* l);
static int qenc_may_hold(const wired_srvloop* l, const stream_frame* sf);

static void gather_wt_land(wired_srvloop* l, const stream_frame* sf) {
  int i = srvloop_wt_slot_for(l, sf);
  if (i >= 0 && srvloop_wt_sig_ready(&l->wt_streams[i], sf)) {
    srvloop_gather_wt_one(sf, &l->wt_streams[i]);
  }
}

/* draft-ietf-webtrans-http3-15 4.3: if the walked frame at `frame` is WT bidi
 * traffic (srvloop_wt_frame_relevant), gather it into its slot. Returns 1 if it
 * was (whether or not a slot was available to hold it — matching
 * srvloop_gather_request's seen semantics). */
int srvloop_gather_wt_frame(wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  if (!srvloop_client_bidi_stream_of(type, frame, &sf)) {
    return 0;
  }
  if (!srvloop_wt_frame_relevant(l, &sf)) {
    return 0;
  }
  gather_wt_land(l, &sf);
  return 1;
}

/* draft-ietf-webtrans-http3-15 4.3: "Endpoints MUST NOT send WT_STREAM as a
 * frame type on HTTP/3 streams other than the very first bytes of a request
 * stream. Receiving this frame type in any other circumstances MUST be
 * treated as a connection error of type H3_FRAME_ERROR." sf's own leading
 * bytes decoding as the WT_STREAM signal at offset 0 is legitimate
 * (srvloop_is_wt_stream_signal/srvloop_sf_is_wt_signalled, checked and consumed
 * elsewhere); this is the SAME decode applied to a frame that is NOT at offset
 * 0 -- the one shape the RFC forbids outright. */
static int is_wt_signal_mid_stream(const stream_frame* sf) {
  return sf->offset != 0 &&
         srvloop_is_wt_stream_signal(wired_span_of(sf->data, (usz)sf->length));
}

/* 1 if the walked frame at `frame` is a client-bidi-id-shaped STREAM frame
 * (srvloop_client_bidi_stream_of, the id space request/WT streams share) whose
 * own data decodes as the WT_STREAM signal at a non-zero offset
 * (is_wt_signal_mid_stream) -- latches l->wt_signal_mid_stream_violation,
 * mirroring srvloop_gather_one_stream_close's latch-only shape. Scanned
 * independent of whether the same stream id was ALSO claimed as WT bidi traffic
 * earlier in this payload or an earlier step: draft-ietf-webtrans-http3-15 4.3
 * draws no exception for an already-classified stream, and a legitimate WT bidi
 * continuation frame never itself re-decodes as the signal varint (the
 * signal is stripped from the stream's data by srvloop_wt_frame_skip, never
 * repeated), so a real WT stream's own application bytes cannot spuriously
 * trigger this. */
static int gather_one_wt_signal_violation(
    wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  if (!srvloop_client_bidi_stream_of(type, frame, &sf)) {
    return 0;
  }
  if (!is_wt_signal_mid_stream(&sf)) {
    return 0;
  }
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
 * (whether or not a slot existed to receive it), mirroring
 * srvloop_gather_wt_frame's own seen semantics. */
int srvloop_gather_server_bidi_frame(
    wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  int          i;
  if (!srvloop_server_bidi_stream_of(type, frame, &sf)) {
    return 0;
  }
  i = wired_srvloop_wt_slot_find(l, sf.stream_id);
  if (i >= 0) {
    srvloop_gather_wt_one(&sf, &l->wt_streams[i]);
  }
  return 1;
}

/* RFC 9000 2.2 / 12.4, draft-ietf-webtrans-http3-15 4.3: write every WT bidi
 * STREAM frame in this payload into its own wt_streams[] slot, at its offset
 * past the signal — independent of whether a request stream is ALSO present
 * in the same payload (a coalesced datagram may carry both). A stream is
 * recognized as WT bidi from its first (offset-0) signal frame; the slot is
 * claimed at that point. Also gathers a server-initiated bidi stream's client
 * reply (srvloop_gather_server_bidi_frame), a disjoint id space (RFC 9000 2.1
 * bits 01 vs. 00) so a single pass over the payload's frames covers both.
 * Returns 1 if any WT bidi frame (either id space) was seen. */
int srvloop_gather_wt_stream(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    seen |= srvloop_gather_server_bidi_frame(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
    seen |= srvloop_gather_wt_frame(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
    seen |= gather_one_wt_signal_violation(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9000 2.1: a client-initiated unidirectional stream has low bits 10. */
int srvloop_is_uni_stream(u64 stream_id) { return (stream_id & 0x03) == 2; }

/* RFC 9114 6.2 / RFC 9204 4.2 / draft-ietf-webtrans-http3-15 4.3: peek (never
 * consumes/advances any state beyond this local decode) an uni stream's
 * offset-0 leading type varint and classify it via wired_h3srv_accept_uni —
 * the SAME classifier that already recognizes control (0x00) / QPACK
 * (0x02/0x03) / WebTransport (0x54), reused rather than reimplemented. An
 * undecodable leading varint classifies as not-accepted (0), same as any
 * other unrecognized type. */
int srvloop_uni_stream_type_accepted(wired_span data) {
  u64 v;
  usz off = 0;
  if (!varint_take(data, &off, &v)) {
    return 0;
  }
  return wired_h3srv_accept_uni(v);
}

/* RFC 9204 4.2 (9204-028): if the leading type varint decodes to the QPACK
 * encoder or decoder stream type, record it on l's peer_qpack_* flags
 * (wired_h3srv_on_peer_qpack) -- a second instance of either type latches
 * l->qpack_stream_violation for the caller driving the loop to close the
 * connection over (H3_STREAM_CREATION_ERROR). Any other (or undecodable)
 * type is a no-op, matching srvloop_uni_stream_type_accepted's own read-only
 * peek. */
void srvloop_uni_stream_type_note_qpack(wired_srvloop* l, wired_span data) {
  u64 v;
  usz off = 0;
  u16 err;
  if (!varint_take(data, &off, &v)) {
    return;
  }
  if (!wired_h3srv_on_peer_qpack(&l->h3, v, &err)) {
    l->qpack_stream_violation = err;
  }
}

/* RFC 9204 4.2: 1 if sf is the offset-0 frame of a stream whose leading type
 * varint names the encoder stream, while none is claimed yet -- such a frame
 * takes the encoder window over from any merely held candidate. */
static int qenc_type_is_encoder(const stream_frame* sf) {
  u64 v;
  usz off = 0;
  return varint_take(wired_span_of(sf->data, (usz)sf->length), &off, &v) &&
         v == H3_STREAM_QPACK_ENCODER;
}

static int qenc_leads_encoder(const wired_srvloop* l, const stream_frame* sf) {
  return sf->offset == 0 && !l->h3.qenc_rx.type_len && qenc_type_is_encoder(sf);
}

/* 1 if sf alone does not say what its stream is: a later chunk, or an
 * offset-0 frame too short to hold the whole type varint. */
static int qenc_frame_untyped(const stream_frame* sf) {
  u64 v;
  usz off = 0;
  return sf->offset != 0 ||
         !varint_take(wired_span_of(sf->data, (usz)sf->length), &off, &v);
}

/* 1 if sf's stream type is already known: typed at offset 0 or let go by
 * the encoder window (l->uni_typed), or a claimed WebTransport uni stream. */
static int qenc_type_known(const wired_srvloop* l, const stream_frame* sf) {
  return wired_srvloop_closed_has(&l->uni_typed, sf->stream_id) ||
         wired_srvloop_wt_uni_slot_find(l, sf->stream_id) >= 0;
}

/* 1 if sf's stream is already known as the control stream or any other
 * typed uni stream. */
static int qenc_stream_known(const wired_srvloop* l, const stream_frame* sf) {
  return (l->ctrl.open && l->ctrl.stream_id == sf->stream_id) ||
         qenc_type_known(l, sf);
}

/* Record sf's stream as typed once its leading type varint is whole at
 * offset 0 (RFC 9114 6.2), so none of its later chunks is ever held. */
void srvloop_uni_type_mark(wired_srvloop* l, const stream_frame* sf) {
  if (!qenc_frame_untyped(sf)) {
    wired_srvloop_closed_mark(&l->uni_typed, sf->stream_id);
  }
}

/* RFC 9000 2.2: 1 if sf may start the encoder window as a candidate -- no
 * stream is held, no encoder stream has shown its type yet, and sf comes from
 * a stream whose type is still unknown (its type varint lost or reordered):
 * its bytes are kept until the type arrives, since the transport has already
 * acknowledged them. ponytail: one candidate at a time; when two streams'
 * types are lost at once, the second's early bytes are dropped. If that one
 * is the encoder stream, its gap never fills: no later insert applies or is
 * acknowledged, so the peer's encoder is left with the static table and the
 * entries acknowledged before, and the stream's credit is never re-granted.
 * Hold one candidate per unknown stream if that is ever seen. */
static int qenc_window_free(const wired_srvloop* l) {
  return !l->h3.qenc_rx.stream_id && !l->h3.peer_qpack_encoder;
}

static int qenc_may_hold(const wired_srvloop* l, const stream_frame* sf) {
  return qenc_window_free(l) && qenc_frame_untyped(sf) &&
         !qenc_stream_known(l, sf);
}

int srvloop_qenc_takes(const wired_srvloop* l, const stream_frame* sf) {
  return qenc_leads_encoder(l, sf) || qenc_may_hold(l, sf);
}
