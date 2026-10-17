#include "app/http3/server/srvloop/dispatch_impl.h"

static int  gather_uni_frame(wired_srvloop* l, u64 type, wired_span frame);
static void queue_rx_datagram(wired_srvloop* l, wired_span payload);
static int  datagram_size_ok(const wired_srvloop* l, usz payload_len);
static void queue_decoded_datagram(wired_srvloop* l, wired_span frame);
static void gather_one_datagram(wired_srvloop* l, u64 type, wired_span frame);

/* draft-ietf-webtrans-http3-15 4.3 / RFC 9114 6.2: classify a client uni
 * stream's leading type and gather it if (and only if) it is 0x54
 * (WebTransport). A recognized-but-not-WT type (control/QPACK,
 * wired_h3srv_accept_uni's existing classifier — reused rather than
 * reimplemented) or an unrecognized type is deliberately left untouched here:
 * srvloop_has_stream/srvloop_feed_or_accept's existing "STREAM frame present ->
 * accepted, content ignored" behavior already covers it unchanged, so this adds
 * classification without altering that path's outcome. */
void srvloop_gather_wt_uni_frame(wired_srvloop* l, const stream_frame* sf) {
  if (sf->offset == 0) {
    srvloop_gather_wt_uni_classify(l, sf);
  }
  srvloop_gather_qpack_enc(l, sf);
  if (!srvloop_wt_uni_frame_relevant(l, sf)) {
    return;
  }
  srvloop_gather_wt_uni_land(l, sf);
}

/* 1 if the walked frame at `frame` is a client uni STREAM frame whose leading
 * (or already-claimed) type classifies as WebTransport (0x54); gathers it into
 * wt_uni_streams[] when so. Returns 1 iff this frame belonged to a uni stream
 * at all (matching srvloop_gather_wt_frame's "seen" semantics for the bidi
 * table) — this lets the caller keep such a payload out of
 * dispatch_non_request's handshake-feed fallback exactly like a bidi/request
 * STREAM frame does. */
static int gather_uni_frame(wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  if (!srvloop_client_uni_stream_of(type, frame, &sf)) {
    return 0;
  }
  srvloop_gather_wt_uni_frame(l, &sf);
  return 1;
}

/* RFC 9000 2.2 / 12.4, draft-ietf-webtrans-http3-15 4.3: write every client
 * uni STREAM frame's WT-typed (0x54) bytes into its own wt_uni_streams[] slot,
 * at its offset past the type varint; a control/QPACK/unrecognized-typed uni
 * stream frame is classified (srvloop_client_uni_stream_of matches) but left
 * otherwise untouched (srvloop_gather_wt_uni_frame's no-op path). Returns 1 if
 * any uni STREAM frame was seen this payload, independent of its type. */
int srvloop_gather_uni_stream(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    seen |= gather_uni_frame(l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9218 7.1 / 10, RFC 9114 6.2.1: reassemble every client uni STREAM frame
 * belonging to the peer's control stream into l->ctrl and apply any newly
 * complete PRIORITY_UPDATE frame (wired_srvloop_ctrl_gather), mirroring
 * srvloop_gather_uni_stream's own walk shape. Returns 1 if any control-stream
 * frame was seen this payload. */
int srvloop_gather_ctrl_priupdate(
    wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    seen |= wired_srvloop_ctrl_gather(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* RFC 9218 7.1 / 9218-013: scan every client bidi (request) STREAM frame this
 * payload carries for a PRIORITY_UPDATE frame, latching l->priupdate_
 * violation on one (wired_srvloop_req_priupdate_gather), mirroring
 * srvloop_gather_ctrl_priupdate's own walk shape. Returns 1 if any
 * request-stream frame was seen this payload. */
int srvloop_gather_req_priupdate(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    seen |= wired_srvloop_req_priupdate_gather(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
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
  bytes_put(wired_mspan_of(slot->buf, cap), &off, wired_span_of(payload.p, n));
  slot->len = n;
  l->rx_datagram_n++;
}

/* RFC 9221 3: this connection's own advertised max_datagram_frame_size (0 =
 * never advertised, this repo's existing sentinel) authorizes payload as a
 * DATAGRAM the peer had a right to send. Delegates to the pre-existing
 * predicate (dgcheck.h); the "we advertised at all" flag is derived here from
 * the 0-sentinel rather than threaded as a separate bit. */
static int datagram_size_ok(const wired_srvloop* l, usz payload_len) {
  return datagram_recv_ok(
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
  if (!dgdeliver_extract(frame, &payload)) {
    return;
  }
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
  if (frame_classify(type) != FK_DATAGRAM) {
    return;
  }
  if (l->rx_datagram_n >= WIRED_SRVLOOP_MAX_RX_DATAGRAMS) {
    return;
  }
  queue_decoded_datagram(l, frame);
}

/* RFC 9221 5: queue every DATAGRAM frame in this payload into l->rx_datagrams,
 * independent of whether the same payload also carries a request or WT bidi
 * stream frame (a coalesced 1-RTT packet may carry all three). Returns 1 if
 * any DATAGRAM frame was seen this payload (whether or not the queue had room
 * to hold it), so the caller can keep such a payload out of
 * dispatch_non_request's handshake-feed fallback. */
int srvloop_gather_rx_datagrams(wired_srvloop* l, const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (frame_classify(fr.type) == FK_DATAGRAM) {
      seen = 1;
    }
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
int srvloop_reset_stream_id(u64 type, wired_span frame, u64* stream_id_out) {
  reset_stream_frame f;
  if (frame_classify(type) != FK_RESET_STREAM) {
    return 0;
  }
  if (reset_stream_decode(frame.p, frame.n, &f) == 0) {
    return 0;
  }
  *stream_id_out = f.stream_id;
  return 1;
}

/* RFC 9000 19.4: 1 if frame is a RESET_STREAM, its stream_id/error_code
 * decoded into *out. Split out of srvloop_gather_one_wt_reset to keep its own
 * branch count at the CCN gate. */
int srvloop_wt_reset_frame(
    u64 type, wired_span frame, reset_stream_frame* out) {
  if (frame_classify(type) != FK_RESET_STREAM) {
    return 0;
  }
  return reset_stream_decode(frame.p, frame.n, out) != 0;
}

/* RFC 9000 19.5: 1 if frame is a STOP_SENDING, its stream_id/error_code
 * decoded into *out. Mirrors srvloop_wt_reset_frame for the other close-shaped
 * frame kind. */
int srvloop_wt_stop_frame(u64 type, wired_span frame, stop_sending_frame* out) {
  if (frame_classify(type) != FK_STOP_SENDING) {
    return 0;
  }
  return stop_sending_decode(frame.p, frame.n, out) != 0;
}
