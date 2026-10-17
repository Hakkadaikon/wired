#include "app/http3/server/srvloop/dispatch_impl.h"

static int  is_server_bidi_stream(u64 stream_id);
static void wt_sig_absorb(u8* sig, u8* have, const stream_frame* sf);
static usz  wt_sig_parse(const u8* sig, u8 have);
static int  wt_slot_for_signal(wired_srvloop* l, const stream_frame* sf);

/* RFC 9220 3 / draft-ietf-webtrans-http3 3: an Extended CONNECT's request
 * stream never carries FIN -- the stream IS the WebTransport session and
 * stays open for its whole lifetime -- so a CONNECT request is complete at
 * its HEADERS frame. 1 if acc currently holds one complete HEADERS frame
 * that decodes to a CONNECT request, or that cannot decode into a request
 * at all (no FIN would change that, and one may never come): the caller
 * then rejects it. The decode lands in in->req, so a section prefix that
 * failed to decode (req.qpack_failed, a connection error) is left to the
 * caller instead. */
int srvloop_connect_headers_complete(
    const wired_h3srv_state*         h3,
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in) {
  usz n = srvloop_acc_headers_frame_len(acc);
  if (n == 0) {
    return 0;
  }
  if (!srvloop_peek_decode_request(h3, acc, in, n, in->req)) {
    return !in->req->qpack_failed;
  }
  return srvloop_req_method_is_connect(in->req);
}

/* A request is complete at FIN (RFC 9114 4.1) or, for a CONNECT, at its
 * complete HEADERS frame (see srvloop_connect_headers_complete -- waiting for a
 * FIN that never comes starved every browser WebTransport session). */
int srvloop_request_complete(
    const wired_h3srv_state*         h3,
    const wired_srvloop_reqacc*      acc,
    const wired_srvloop_dispatch_in* in) {
  if (*acc->done) {
    return 0;
  }
  if (*acc->fin) {
    return 1;
  }
  return srvloop_connect_headers_complete(h3, acc, in);
}

/* 1 if the walked frame at `frame` is ANY client-bidi-id-shaped STREAM frame
 * (low bits 00) — the id space a WT bidi stream shares with request streams,
 * unlike srvloop_request_stream_of this does NOT exclude a WT-signalled stream,
 * since this is exactly the classifier srvloop_gather_wt_stream needs to find
 * WT frames srvloop_request_stream_of deliberately skips. */
int srvloop_client_bidi_stream_of(
    u64 type, wired_span frame, stream_frame* sf) {
  return srvloop_is_stream(type) && frame_get_stream(frame.p, frame.n, sf) &&
         srvloop_is_request_stream(sf->stream_id);
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
 * srvloop_client_bidi_stream_of's shape for the separate id space. */
int srvloop_server_bidi_stream_of(
    u64 type, wired_span frame, stream_frame* sf) {
  return srvloop_is_stream(type) && frame_get_stream(frame.p, frame.n, sf) &&
         is_server_bidi_stream(sf->stream_id);
}

/* Copy sf's bytes overlapping [0, WT_SIG_CAP) into sig[] by absolute stream
 * offset, raising *have to the highest byte filled. The signal is a strict
 * prefix of the stream, so frames past it never overlap this range. */
static void wt_sig_absorb(u8* sig, u8* have, const stream_frame* sf) {
  usz off = (usz)sf->offset;
  usz n;
  if (off >= WT_SIG_CAP) {
    return;
  }
  n = (usz)u64_min((u64)sf->length, (u64)(WT_SIG_CAP - off));
  bytes_put(wired_mspan_of(sig, WT_SIG_CAP), &off, wired_span_of(sf->data, n));
  if (off > *have) {
    *have = (u8)off;
  }
}

/* The two leading varints' (type/signal + session id) combined encoded
 * length, 0 while they have not both fully arrived in sig[0..have). The
 * session id's own length must come from a parse, never be assumed: skipping
 * only the type varint once left the session id as a leading garbage byte on
 * every request line (a real webtransport-go interop run found it), and
 * freezing the length from a first frame carrying the type varint alone
 * leaked the id the same way (a real flupke interop run found that). */
static usz wt_sig_parse(const u8* sig, u8 have) {
  u64        v;
  usz        off = 0;
  wired_span s   = wired_span_of(sig, have);
  if (!varint_take(s, &off, &v)) {
    return 0;
  }
  if (!varint_take(s, &off, &v)) {
    return 0;
  }
  return off;
}

/* Absorb sf into a slot's pending-signal buffer and resolve *len once both
 * varints parse. Returns 1 when the signal is resolved (landing may
 * proceed -- immediately so for a pre-claimed reply stream, whose *pending
 * is never set), 0 while it is still incomplete (sf ended inside the
 * signal; nothing of it is application data). */
int srvloop_wt_sig_resolve(
    u8* sig, u8* have, u8* pending, usz* len, const stream_frame* sf) {
  if (!*pending) {
    return 1;
  }
  wt_sig_absorb(sig, have, sf);
  *len = wt_sig_parse(sig, *have);
  if (!*len) {
    return 0;
  }
  *pending = 0;
  return 1;
}

/* draft-ietf-webtrans-http3-15 4.3: bytes of THIS frame's own data that are
 * the leading signal, not application data — the part of [offset,
 * offset+length) that overlaps [0, sig_len). Nonzero for any frame starting
 * inside the signal (usually the offset-0 frame, but a split signal's
 * session id can arrive in a later frame). */
usz srvloop_wt_frame_skip(const stream_frame* sf, usz sig_len) {
  if (sf->offset >= sig_len) {
    return 0;
  }
  return (usz)u64_min(sig_len - sf->offset, sf->length);
}

/* sf's absolute post-signal stream offset -- its first application byte's
 * position with the signal's bytes excised. Saturates to 0 for a frame that
 * ends inside the signal (n is then 0, nothing lands). */
u64 srvloop_wt_frame_abs(const stream_frame* sf, usz sig_len, usz skip) {
  u64 end = sf->offset + skip;
  return end > sig_len ? end - sig_len : 0;
}

/* draft-ietf-webtrans-http3-15 4.3: land one WT bidi STREAM frame's
 * application bytes into slot->buf, honoring the slot's receive window (RFC
 * 9000 2.2's offset-indexed, reordering-tolerant reassembly — a frame may
 * arrive with a gap before it, or entirely re-cover already-delivered bytes).
 * `skip` is how many bytes of THIS frame's own data are the signal rather
 * than application data (nonzero only for the offset-0 frame, see
 * srvloop_wt_frame_skip); `abs_off` is the frame's absolute post-signal stream
 * offset — every frame's stream-level offset is shifted left by the signal's
 * FULL encoded length (slot->sig_len), since the signal itself never
 * occupies any stream position, not just the offset-0 frame's own skip.
 * wired_srvloop_wt_window_accept answers where (and how much of) this lands
 * in slot->buf; bytes outside the currently open window are dropped (see its
 * own doc). */
void srvloop_gather_wt_one(
    const stream_frame* sf, wired_srvloop_wt_stream_slot* slot) {
  usz skip    = srvloop_wt_frame_skip(sf, slot->sig_len);
  u64 abs_off = srvloop_wt_frame_abs(sf, slot->sig_len, skip);
  usz n       = (usz)sf->length - skip;
  usz rel_off, accepted;
  wired_srvloop_wt_window_accept(&slot->win, abs_off, n, &rel_off, &accepted);
  if (accepted) {
    bytes_put(
        wired_mspan_of(slot->buf, sizeof slot->buf), &rel_off,
        wired_span_of(sf->data + skip + (n - accepted), accepted));
  }
  if (sf->fin) {
    slot->fin     = 1;
    slot->fin_off = abs_off + n;
  }
}

/* draft-ietf-webtrans-http3-15 4.3: claim the wt_streams slot for a
 * newly-signalled stream, marking its leading signal pending so
 * srvloop_wt_sig_resolve settles sig_len from the accumulated leading bytes
 * (which may span several frames). A full table queues the stream for an
 * explicit refusal (RFC 9114 8.1, wired_srvloop_wt_refuse) and returns -1. */
static int wt_slot_for_signal(wired_srvloop* l, const stream_frame* sf) {
  int i = wired_srvloop_wt_slot_claim(l, sf->stream_id);
  if (i < 0) {
    wired_srvloop_wt_refuse(l, sf->stream_id);
    return -1;
  }
  l->wt_streams[i].sig_pending = 1;
  return i;
}

/* draft-ietf-webtrans-http3-15 4.3: the wt_streams[] slot index for sf, which
 * srvloop_wt_frame_relevant already confirmed is WT bidi traffic — the stream's
 * existing slot (a retransmitted signal frame included), else claim one on
 * the leading signal frame. */
int srvloop_wt_slot_for(wired_srvloop* l, const stream_frame* sf) {
  int i = wired_srvloop_wt_slot_find(l, sf->stream_id);
  if (i >= 0 || sf->offset != 0) {
    return i;
  }
  return wt_slot_for_signal(l, sf);
}

/* draft-ietf-webtrans-http3-15 4.3: land sf (already confirmed WT bidi
 * traffic) into its slot, claiming one on the leading signal frame. A full
 * table (i<0) still counts the frame as seen, matching stream_slot_claim's
 * fixed-capacity fallback of dropping the data but not the classification. */
/* srvloop_wt_sig_resolve over a bidi slot's own signal fields. */
int srvloop_wt_sig_ready(
    wired_srvloop_wt_stream_slot* s, const stream_frame* sf) {
  return srvloop_wt_sig_resolve(
      s->sig, &s->sig_have, &s->sig_pending, &s->sig_len, sf);
}
