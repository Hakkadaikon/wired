#include "app/http3/server/srvloop/dispatch_impl.h"

static int  qenc_owns(wired_srvloop* l, const stream_frame* sf);
static void qenc_note_released(wired_srvloop* l, u64 id);
static int  is_wt_uni_stream_type(wired_span data);
static int  sf_is_wt_uni_typed(const stream_frame* sf);
static int  wt_uni_slot_for_type(wired_srvloop* l, const stream_frame* sf);
static int  wt_uni_slot_for(wired_srvloop* l, const stream_frame* sf);
static int  wt_uni_sig_ready(
    wired_srvloop_wt_uni_stream_slot* s, const stream_frame* sf);

/* 1 if sf belongs in the encoder window, taking the window for its stream
 * when it leads the encoder stream or may be held as a candidate. */
static int qenc_owns(wired_srvloop* l, const stream_frame* sf) {
  if (sf->stream_id == l->h3.qenc_rx.stream_id) return 1;
  if (!srvloop_qenc_takes(l, sf)) return 0;
  qdyn_encrx_take(&l->h3.qenc_rx, sf->stream_id);
  return 1;
}

/* The window let go of stream id (its type turned out not to be the
 * encoder's): its type is known from now on. */
static void qenc_note_released(wired_srvloop* l, u64 id) {
  if (!l->h3.qenc_rx.stream_id) wired_srvloop_closed_mark(&l->uni_typed, id);
}

/* RFC 9204 4.2 / 4.3: feed sf, if it belongs to the encoder window, at its
 * stream offset; every instruction it completes is applied to l->h3.qdyn, an
 * invalid one latches l->qpack_stream_violation. */
void srvloop_gather_qpack_enc(wired_srvloop* l, const stream_frame* sf) {
  u16 err = 0;
  if (!qenc_owns(l, sf)) return;
  if (!qdyn_encrx_feed(
          &l->h3.qenc_rx, sf->offset, wired_span_of(sf->data, (usz)sf->length),
          &l->h3.qdyn, l->h3.qpack_max_table_capacity, &err))
    l->qpack_stream_violation = err;
  qenc_note_released(l, sf->stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: 1 if this uni stream's very first bytes
 * (an offset-0 STREAM frame's data) decode as the WT uni stream type varint
 * (0x54, RFC 9114 6.2/RFC 9220). Unlike a WT bidi stream's signal byte, a uni
 * stream's type is unambiguous and never mid-stream — only offset 0 is ever
 * checked, matching srvloop_is_wt_stream_signal's own read-only peek (no state
 * is consumed beyond the local varint decode). */
static int is_wt_uni_stream_type(wired_span data) {
  u64 v;
  usz off = 0;
  if (!varint_take(data, &off, &v)) return 0;
  return v == H3_STREAM_WEBTRANSPORT;
}

/* 1 if sf is the stream's first-sighted (offset 0) frame and its leading
 * bytes decode as the WT uni stream type — the classification this slice adds
 * for a uni stream (mirrors srvloop_sf_is_wt_signalled's bidi counterpart). */
static int sf_is_wt_uni_typed(const stream_frame* sf) {
  return sf->offset == 0 &&
         is_wt_uni_stream_type(wired_span_of(sf->data, (usz)sf->length));
}

/* 1 if the walked frame at `frame` is a client uni STREAM frame (low bits 10)
 * — the id space wt_uni_streams draws from, decoded into sf for the caller. */
int srvloop_client_uni_stream_of(u64 type, wired_span frame, stream_frame* sf) {
  return srvloop_is_stream(type) && frame_get_stream(frame.p, frame.n, sf) &&
         srvloop_is_uni_stream(sf->stream_id);
}

/* draft-ietf-webtrans-http3-15 4.3: this uni frame is either the stream's
 * leading type byte (offset 0, decodes to 0x54) or belongs to a uni stream
 * already claimed in wt_uni_streams[] by an earlier typed frame. */
int srvloop_wt_uni_frame_relevant(
    const wired_srvloop* l, const stream_frame* sf) {
  return sf_is_wt_uni_typed(sf) ||
         wired_srvloop_wt_uni_slot_find(l, sf->stream_id) >= 0;
}

/* draft-ietf-webtrans-http3-15 4.3: land one WT uni STREAM frame's application
 * bytes into slot->buf, mirroring srvloop_gather_wt_one's bidi counterpart
 * exactly (skip whatever part of this frame is still the leading signal, shift
 * every frame's offset back by the signal's full encoded length, honor the
 * slot's receive window). */
void srvloop_gather_wt_uni_one(
    const stream_frame* sf, wired_srvloop_wt_uni_stream_slot* slot) {
  usz skip    = srvloop_wt_frame_skip(sf, slot->type_len);
  u64 abs_off = srvloop_wt_frame_abs(sf, slot->type_len, skip);
  usz n       = (usz)sf->length - skip;
  usz rel_off, accepted;
  wired_srvloop_wt_window_accept(&slot->win, abs_off, n, &rel_off, &accepted);
  if (accepted)
    bytes_put(
        wired_mspan_of(slot->buf, sizeof slot->buf), &rel_off,
        wired_span_of(sf->data + skip + (n - accepted), accepted));
  if (sf->fin) {
    slot->fin     = 1;
    slot->fin_off = abs_off + n;
  }
}

/* draft-ietf-webtrans-http3-15 4.3: find-or-claim the wt_uni_streams slot for
 * a newly-typed stream, marking its leading signal (type varint + session id
 * varint) pending so srvloop_wt_sig_resolve settles type_len from the
 * accumulated leading bytes (which may span several frames). */
static int wt_uni_slot_for_type(wired_srvloop* l, const stream_frame* sf) {
  int i = wired_srvloop_wt_uni_slot_claim(l, sf->stream_id);
  if (i < 0) return -1;
  l->wt_uni_streams[i].sig_pending = 1;
  return i;
}

/* draft-ietf-webtrans-http3-15 4.3: the wt_uni_streams[] slot index for sf,
 * which srvloop_wt_uni_frame_relevant already confirmed is WT uni traffic. */
static int wt_uni_slot_for(wired_srvloop* l, const stream_frame* sf) {
  if (sf->offset == 0) return wt_uni_slot_for_type(l, sf);
  return wired_srvloop_wt_uni_slot_find(l, sf->stream_id);
}

/* qlog stream_frame_received (RFC 9000 19.8) for one WT uni STREAM frame
 * this connection's receive side just gathered, attributed via
 * l->qlog_path/qlog_group (srvrun_conn.qlog_slot's doc) -- the received-side
 * counterpart to srvrun_qlog_stream_sent. No-op without a qlog path. */
void dispatch_qlog_stream_received(wired_srvloop* l, const stream_frame* sf) {
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

/* srvloop_wt_sig_resolve over a uni slot's own signal fields. */
static int wt_uni_sig_ready(
    wired_srvloop_wt_uni_stream_slot* s, const stream_frame* sf) {
  return srvloop_wt_sig_resolve(
      s->sig, &s->sig_have, &s->sig_pending, &s->type_len, sf);
}

/* draft-ietf-webtrans-http3-15 4.3: land sf (already confirmed WT uni
 * traffic) into its slot, claiming one on the leading type frame. */
void srvloop_gather_wt_uni_land(wired_srvloop* l, const stream_frame* sf) {
  int i = wt_uni_slot_for(l, sf);
  if (i >= 0 && wt_uni_sig_ready(&l->wt_uni_streams[i], sf))
    srvloop_gather_wt_uni_one(sf, &l->wt_uni_streams[i]);
  dispatch_qlog_stream_received(l, sf);
}

/* Classify this uni stream's offset-0 leading type varint: a read-only peek
 * (wired_h3srv_accept_uni, its result unused here on purpose -- see
 * srvloop_gather_wt_uni_frame's own doc) plus recording a QPACK encoder/decoder
 * type on l->h3.peer_qpack_* (RFC 9204 4.2), and marking the stream typed for
 * the encoder window (srvloop_uni_type_mark). Split out of
 * srvloop_gather_wt_uni_frame so its own branch count stays at the CCN gate. */
void srvloop_gather_wt_uni_classify(wired_srvloop* l, const stream_frame* sf) {
  wired_span data = wired_span_of(sf->data, (usz)sf->length);
  srvloop_uni_stream_type_accepted(data);
  srvloop_uni_stream_type_note_qpack(l, data);
  srvloop_uni_type_mark(l, sf);
}
