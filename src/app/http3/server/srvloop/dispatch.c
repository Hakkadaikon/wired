#include "app/http3/server/srvloop/dispatch_impl.h"

static int sf_is_request(const wired_srvloop* l, const stream_frame* sf);
static int stream_is_request(const wired_srvloop* l, const u8* frame, usz rem);
static int is_request_frame(
    const wired_srvloop* l, u64 type, const u8* frame, usz rem);
static void gather_one(const stream_frame* sf, wired_srvloop_reqacc* acc);
static int  dispatch_bytes_eq7(const u8* m, const u8* want);
static const qpack_dyn* dispatch_qdyn(const wired_h3srv_state* h3);

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
int srvloop_is_stream(u64 type) {
  return type >= FRAME_STREAM_BASE && type <= FRAME_STREAM_BASE + 7;
}

/* RFC 9000 2.1: a STREAM is a client-initiated bidirectional request stream
 * (carrying HTTP/3 HEADERS) iff its low two bits are 0. The 0x2 bit marks a
 * unidirectional stream (HTTP/3 control / QPACK encoder+decoder, RFC 9114 6.2),
 * which curl opens before the request and must NOT be treated as a request. */
int srvloop_is_request_stream(u64 stream_id) { return (stream_id & 0x03) == 0; }

/* draft-ietf-webtrans-http3-15 4.3: 1 if this bidi stream's very first bytes
 * (an offset-0 STREAM frame's data) decode as the WT_STREAM signal varint
 * (value 0x41). Only offset 0 is ever checked here — the signal MUST be the
 * stream's leading bytes, so a later (offset>0) frame is never mistaken for
 * one. Truncated/undecodable leading bytes are not the signal (0). */
int srvloop_is_wt_stream_signal(wired_span data) {
  u64 v;
  usz off = 0;
  if (!varint_take(data, &off, &v)) {
    return 0;
  }
  return v == H3_STREAM_WEBTRANSPORT_BIDI;
}

/* 1 if sf is the stream's first-sighted (offset 0) frame and its leading bytes
 * are the WT_STREAM signal — the one case that overrides an id-based request
 * classification (see sf_is_request below). Any other frame (offset>0) is
 * never checked against the signal, matching "MUST be the leading bytes". */
int srvloop_sf_is_wt_signalled(const stream_frame* sf) {
  return sf->offset == 0 &&
         srvloop_is_wt_stream_signal(wired_span_of(sf->data, (usz)sf->length));
}

/* draft-ietf-webtrans-http3-15 4.3: this frame is either the stream's leading
 * signal (offset 0, decodes to 0x41) or belongs to a stream already claimed
 * in wt_streams[] by an earlier signal frame. Either way it is WT bidi
 * traffic, not a request. l may be 0 (a caller exercising only the request
 * path directly, see wired_srvloop_dispatch_ctx's doc) — a stream can only be
 * ALREADY claimed via a loop that does not exist, so only the offset-0 signal
 * check applies then. */
int srvloop_wt_frame_relevant(const wired_srvloop* l, const stream_frame* sf) {
  if (srvloop_sf_is_wt_signalled(sf)) {
    return 1;
  }
  return l && wired_srvloop_wt_slot_find(l, sf->stream_id) >= 0;
}

/* 1 if sf is a client bidi request stream — i.e. its id classifies as request
 * and it is not WT bidi traffic (srvloop_wt_frame_relevant: either this frame
 * is the leading 0x41 signal, or an earlier frame already claimed this stream
 * in l->wt_streams[]). A WT bidi stream must never be committed to the HTTP/3
 * request-reassembly path, at ANY offset — checking only offset 0 here would
 * let a WT stream's post-signal continuation frame (offset>0) be misread as
 * request data (draft-ietf-webtrans-http3-15 4.3's leading-bytes requirement
 * is about where the SIGNAL may appear, not about which frames of an already-
 * classified stream still count as application data). Full routing to a
 * wired_wt_session is Phase 7b future work (see wired_srvloop_dispatch's
 * header doc); per this call's scope, a WT stream is simply not treated as a
 * request (srvloop_feed_or_accept's existing "accepted but ignored" path takes
 * it from here). */
static int sf_is_request(const wired_srvloop* l, const stream_frame* sf) {
  return srvloop_is_request_stream(sf->stream_id) &&
         !srvloop_wt_frame_relevant(l, sf);
}

/* 1 if the STREAM frame at `frame` is a client bidi request stream. */
static int stream_is_request(const wired_srvloop* l, const u8* frame, usz rem) {
  stream_frame sf;
  if (frame_get_stream(frame, rem, &sf) == 0) {
    return 0;
  }
  return sf_is_request(l, &sf);
}

/* 1 if the walked frame of `type` at `frame` is a client bidi request STREAM.
 */
static int is_request_frame(
    const wired_srvloop* l, u64 type, const u8* frame, usz rem) {
  return srvloop_is_stream(type) && stream_is_request(l, frame, rem);
}

/* RFC 9114 4.1: hand the (reassembled) request STREAM frame to the HTTP/3
 * request decoder. */
int dispatch_stream(
    wired_h3srv_state*               h3,
    wired_span                       frame,
    const wired_srvloop_dispatch_in* in) {
  wired_h3srv_req_in rin = {frame, in->scratch};
  if (!wired_h3srv_on_request(h3, &rin, in->req)) {
    return 0;
  }
  *in->got_request = 1;
  return 1;
}

/* Raise the accumulator high-water mark to end, clamped to acc->cap. */
void srvloop_bump_len(wired_srvloop_reqacc* acc, usz end) {
  usz hi = end < acc->cap ? end : acc->cap;
  if (hi > *acc->len) {
    *acc->len = hi;
  }
}

/* RFC 9000 2.2: write one request STREAM frame's data into acc->buf at the
 * frame's own offset (offset-indexed reassembly, robust to reordering within
 * acc->cap), advance the high-water mark, and OR its FIN into acc->fin.
 * Data past acc->cap is truncated (the part that fits is kept, so a request
 * that overflows still shows its leading HEADERS frame). */
static void gather_one(const stream_frame* sf, wired_srvloop_reqacc* acc) {
  usz off = (usz)sf->offset;
  if (off >= acc->cap) {
    return;
  }
  bytes_put(
      wired_mspan_of(acc->buf, acc->cap), &off,
      wired_span_of(sf->data, (usz)u64_min(sf->length, acc->cap - off)));
  srvloop_bump_len(acc, (usz)sf->offset + (usz)sf->length);
  *acc->fin |= sf->fin;
}

/* 1 if the walked frame is a request STREAM frame and decodes into sf. l is
 * threaded through to is_request_frame so a WT bidi stream's continuation
 * frame (offset>0, already claimed in l->wt_streams[]) is excluded here too,
 * not just its own offset-0 signal frame. */
int srvloop_request_stream_of(
    const wired_srvloop* l, u64 type, wired_span frame, stream_frame* sf) {
  return is_request_frame(l, type, frame.p, frame.n) &&
         frame_get_stream(frame.p, frame.n, sf);
}

/* RFC 9000 2.2 / 12.4, RFC 9114 6.2: write every client bidi (request) STREAM
 * frame in this payload into the cross-datagram accumulator at its offset,
 * skipping PADDING/ACK and the unidirectional STREAMs (control / QPACK) curl
 * sends first. Returns 1 if any request-stream frame was seen this datagram. */
int srvloop_gather_request(
    const wired_srvloop*  l,
    const u8*             payload,
    usz                   len,
    wired_srvloop_reqacc* acc) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  stream_frame   sf;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (srvloop_request_stream_of(
            l, fr.type, wired_span_of(fr.start, fr.remaining), &sf)) {
      gather_one(&sf, acc);
      seen = 1;
    }
  }
  return seen;
}

/* RFC 9000 2.2: the request is complete once FIN closed the stream and it has
 * not already been decoded/answered (curl FINs the request's last STREAM). */
/* Bytes of acc up to the end of its leading HTTP/3 HEADERS frame, past any
 * unknown/reserved (GREASE) frames ahead of it (RFC 9114 7.2.8 / 9: ignored
 * on request streams too), or 0 when no complete HEADERS is buffered yet or
 * a frame that must be rejected (e.g. DATA, 4.1) precedes it. */
usz srvloop_acc_headers_frame_len(const wired_srvloop_reqacc* acc) {
  return wired_h3reqdrive_headers_end(wired_span_of(acc->buf, *acc->len));
}

/* Constant-shape 7-octet compare (the CONNECT method token). */
static int dispatch_bytes_eq7(const u8* m, const u8* want) {
  u8 d = 0;
  for (usz i = 0; i < 7; i++) {
    d |= m[i] ^ want[i];
  }
  return d == 0;
}

int srvloop_req_method_is_connect(const wired_h3reqdrive_req* r) {
  static const u8 want[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  if (!r->method || r->method_len != sizeof want) {
    return 0;
  }
  return dispatch_bytes_eq7(r->method, want);
}

/* The connection's dynamic table, none for a test stub with no h3 state. */
static const qpack_dyn* dispatch_qdyn(const wired_h3srv_state* h3) {
  return h3 ? &h3->qdyn : 0;
}

/* Wrap acc's first n bytes as a STREAM frame in in->wrap (the same caller-
 * owned buffer srvloop_drive_complete reuses right after) and decode the
 * request into *r against the connection's dynamic table (RFC 9204 2.2: the
 * peer's encoder may reference it in any section, the CONNECT included).
 * Returns 1 on a successful decode. */
int srvloop_peek_decode_request(
    const wired_h3srv_state*         h3,
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in,
    usz                              n,
    wired_h3reqdrive_req*            r) {
  stream_frame f  = {0, 0, n, acc->buf, 0};
  wired_obuf   ob = obuf_of(in->wrap.p, in->wrap.n);
  if (!appdata_stream_frame(&f, &ob)) {
    return 0;
  }
  return wired_h3reqdrive_recv_get_dyn(
      wired_span_of(in->wrap.p, ob.len), in->scratch, dispatch_qdyn(h3), r);
}
