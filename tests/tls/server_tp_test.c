#include "app/http3/server/srvloop/srvloop.h" /* WIRED_SRVLOOP_WT_BUF_CAP */
#include "test.h"

/* RFC 9000 18.2. The DCID/SCID the build is told to advertise. */
static const u8 odcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
static const u8 scid[]  = {0x11, 0x22, 0x33, 0x44, 0x55};

/* Build server TPs for (odcid, scid) into buf; returns the encoded length. */
static usz stp_build(u8* buf, usz cap) {
  wired_obuf ob = quic_obuf_of(buf, cap);
  wired_span od = wired_span_of(odcid, sizeof(odcid));
  wired_span sc = wired_span_of(scid, sizeof(scid));
  return quic_stp_build_server(od, sc, &ob) ? ob.len : 0;
}

/* quic_stp_parse for an integer-valued parameter, discarding the bytes view.
 */
static int parse_int(wired_span tp, u64 param_id, u64* v) {
  quic_stp_out out = {v, 0};
  return quic_stp_parse(tp, param_id, &out);
}

/* Append one integer TP at ob->len (mirrors stp/server_tp.c's put_int). */
static int put_int_at(wired_obuf* ob, u64 id, u64 val) {
  wired_obuf tail = quic_obuf_of(ob->p + ob->len, ob->cap - ob->len);
  usz        w    = quic_tparam_put_int(&tail, id, val);
  ob->len += w;
  return w != 0;
}

static void test_server_tp_ids_and_values(void) {
  u8           buf[256];
  u64          v;
  wired_span   b;
  quic_stp_out bo = {0, &b};
  usz          n  = stp_build(buf, sizeof(buf));
  CHECK(n != 0);
  wired_span tp = wired_span_of(buf, n);

  /* RFC 9000 7.3: original_destination_connection_id carries the client DCID.
   */
  CHECK(
      quic_stp_parse(tp, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &bo) == 1);
  CHECK(
      b.n == sizeof(odcid) &&
      quic_tparam_cid_match(b, wired_span_of(odcid, sizeof(odcid))));

  /* RFC 9000 7.3: initial_source_connection_id carries the server SCID. */
  CHECK(quic_stp_parse(tp, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &bo) == 1);
  CHECK(
      b.n == sizeof(scid) &&
      quic_tparam_cid_match(b, wired_span_of(scid, sizeof(scid))));

  CHECK(parse_int(tp, QUIC_TP_MAX_IDLE_TIMEOUT, &v) && v == 30000);
  /* 10,000,000 matches the connection-wide default the mainstream stacks
   * benchmark with (quiche's CLI default), so untuned cross-implementation
   * runs start from equal preconditions. Safe above the fixed receive
   * buffers: the per-stream windows below carry the actual buffering
   * promise, and they bind before the connection-wide limit does. */
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_DATA, &v) && v == 10000000);
  /* An advertised per-stream window is a promise to buffer that many bytes
   * past delivery. bidi_local and uni land in srvloop's fixed WT reassembly
   * windows, so they must never exceed WIRED_SRVLOOP_WT_BUF_CAP: a larger
   * advertisement let a compliant sender outrun the buffer, whose overflow
   * bytes were clipped-yet-ACKed -- an unfillable stream gap that froze
   * delivery for good (the moqt_chat voice track died 10 s into every
   * call this way). server_tp.c cannot include srvloop.h itself (tls layer
   * sits below app), so this test is where the two constants are pinned
   * together. */
  CHECK(
      parse_int(tp, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, &v) &&
      v == WIRED_SRVLOOP_WT_BUF_CAP);
  CHECK(
      parse_int(tp, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, &v) &&
      v == 262144);
  CHECK(
      parse_int(tp, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, &v) &&
      v == WIRED_SRVLOOP_WT_BUF_CAP);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v) && v == 100);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_UNI, &v) && v == 100);
}

/* RFC 9000 7.3: after a Retry, retry_source_connection_id carries the
 * Retry's SCID; without one the parameter is absent entirely (a peer that
 * saw no Retry treats an unexpected one as TRANSPORT_PARAMETER_ERROR). */
static void test_server_tp_retry_scid(void) {
  u8           buf[256];
  wired_span   b;
  quic_stp_out bo     = {0, &b};
  const u8     rsc[6] = {9, 8, 7, 6, 5, 4};
  wired_obuf   ob     = quic_obuf_of(buf, sizeof buf);
  wired_span   od     = wired_span_of(odcid, sizeof odcid);
  wired_span   sc     = wired_span_of(scid, sizeof scid);
  CHECK(
      quic_stp_build_server_ret(
          od, sc, wired_span_of(rsc, 6), wired_span_of(0, 0), 0, &ob) == 1);
  {
    wired_span tp = wired_span_of(buf, ob.len);
    CHECK(quic_stp_parse(tp, QUIC_TP_RETRY_SOURCE_CONNECTION_ID, &bo) == 1);
    CHECK(b.n == 6 && quic_tparam_cid_match(b, wired_span_of(rsc, 6)));
  }
  ob.len = 0;
  CHECK(
      quic_stp_build_server_ret(
          od, sc, wired_span_of(0, 0), wired_span_of(0, 0), 0, &ob) == 1);
  CHECK(
      quic_stp_parse(
          wired_span_of(buf, ob.len), QUIC_TP_RETRY_SOURCE_CONNECTION_ID,
          &bo) == 0);
}

/* RFC 9000 10.3.1/18.2: a 16-byte stateless_reset_token supplied to the
 * build lands in the TPs verbatim; an empty span omits the TP entirely (a
 * server that never sends resets advertises none). */
static void test_server_tp_stateless_reset_token(void) {
  u8           buf[256];
  wired_span   b;
  quic_stp_out bo = {0, &b};
  u8           tok[16];
  wired_obuf   ob = quic_obuf_of(buf, sizeof buf);
  wired_span   od = wired_span_of(odcid, sizeof odcid);
  wired_span   sc = wired_span_of(scid, sizeof scid);
  for (usz i = 0; i < 16; i++) tok[i] = (u8)(0xe0 + i);
  CHECK(
      quic_stp_build_server_ret(
          od, sc, wired_span_of(0, 0), wired_span_of(tok, 16), 0, &ob) == 1);
  {
    wired_span tp = wired_span_of(buf, ob.len);
    CHECK(quic_stp_parse(tp, QUIC_TP_STATELESS_RESET_TOKEN, &bo) == 1);
    CHECK(b.n == 16 && quic_tparam_cid_match(b, wired_span_of(tok, 16)));
  }
  ob.len = 0;
  CHECK(
      quic_stp_build_server_ret(
          od, sc, wired_span_of(0, 0), wired_span_of(0, 0), 0, &ob) == 1);
  CHECK(
      quic_stp_parse(
          wired_span_of(buf, ob.len), QUIC_TP_STATELESS_RESET_TOKEN, &bo) == 0);
}

static void test_server_tp_no_room(void) {
  u8 buf[8];
  CHECK(stp_build(buf, sizeof(buf)) == 0);
}

static void test_server_tp_parse_absent(void) {
  u8  buf[256];
  u64 v = 7;
  usz n = stp_build(buf, sizeof(buf));
  CHECK(n != 0);
  /* stateless_reset_token (0x02) is never advertised here. */
  CHECK(
      parse_int(wired_span_of(buf, n), QUIC_TP_STATELESS_RESET_TOKEN, &v) == 0);
  CHECK(v == 7);
}

/* A client's transport parameters, parsed for the values the server needs. */
static void test_client_tp_extract(void) {
  u8         buf[64];
  u64        v;
  wired_obuf ob = quic_obuf_of(buf, sizeof(buf));
  CHECK(put_int_at(&ob, QUIC_TP_INITIAL_MAX_DATA, 49152));
  CHECK(put_int_at(&ob, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 3));
  wired_span tp = wired_span_of(buf, ob.len);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_DATA, &v) && v == 49152);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v) && v == 3);
}

/* Find integer TP `want` in a built blob and return its varint value. */
static int tp_int_value(const u8* tp, usz n, u64 want, u64* val) {
  usz off = 0;
  while (off < n) {
    u64        id;
    wired_span v;
    usz used = quic_tparam_get_blob(wired_span_of(tp + off, n - off), &id, &v);
    if (!used) return 0;
    off += used;
    if (id != want) continue;
    usz voff = 0;
    return quic_varint_take(v, &voff, val);
  }
  return 0;
}

/* Custom limits override the advertised defaults; zero fields keep them. */
static void test_server_tp_tunable_limits(void) {
  u8              od[4] = {1, 2, 3, 4}, sc[4] = {5, 6, 7, 8};
  u8              tp[256];
  wired_obuf      ob  = {tp, sizeof tp, 0};
  quic_stp_limits lim = {2000000, 5, 9, 0};
  u64             v   = 0;
  CHECK(quic_stp_build_server_lim(
      wired_span_of(od, 4), wired_span_of(sc, 4), &lim, &ob));
  CHECK(tp_int_value(tp, ob.len, 0x04, &v) && v == 2000000);
  CHECK(tp_int_value(tp, ob.len, 0x08, &v) && v == 5);
  CHECK(tp_int_value(tp, ob.len, 0x09, &v) && v == 9);
  ob.len = 0;
  CHECK(quic_stp_build_server(wired_span_of(od, 4), wired_span_of(sc, 4), &ob));
  CHECK(tp_int_value(tp, ob.len, 0x04, &v) && v == 10000000);
  CHECK(tp_int_value(tp, ob.len, 0x08, &v) && v == 100);
}

/* max_datagram_frame_size (0x20, RFC 9221 3) is absent by default (do not
 * advertise DATAGRAM support until delivery is wired), and present with the
 * caller's value once opted in. */
static void test_server_tp_datagram_frame_size(void) {
  u8              od[4] = {1, 2, 3, 4}, sc[4] = {5, 6, 7, 8};
  u8              tp[256];
  wired_obuf      ob   = {tp, sizeof tp, 0};
  quic_stp_limits none = {0, 0, 0, 0};
  u64             v    = 7;
  CHECK(quic_stp_build_server_lim(
      wired_span_of(od, 4), wired_span_of(sc, 4), &none, &ob));
  CHECK(tp_int_value(tp, ob.len, 0x20, &v) == 0);
  CHECK(v == 7);

  ob.len                   = 0;
  quic_stp_limits opted_in = {0, 0, 0, 65535};
  CHECK(quic_stp_build_server_lim(
      wired_span_of(od, 4), wired_span_of(sc, 4), &opted_in, &ob));
  CHECK(tp_int_value(tp, ob.len, 0x20, &v) && v == 65535);

  ob.len = 0;
  CHECK(quic_stp_build_server(wired_span_of(od, 4), wired_span_of(sc, 4), &ob));
  CHECK(tp_int_value(tp, ob.len, 0x20, &v) == 0);
}

/* reset_stream_at (0x1d, draft-ietf-quic-reliable-stream-reset 4): sent
 * unconditionally with an empty value -- id and length are each a 1-byte
 * varint (0x1d < 0x40, length 0 < 0x40), no content bytes: {0x1d, 0x00}. */
static void test_server_tp_reset_stream_at_empty(void) {
  u8         buf[256];
  wired_span found;
  u64        id = 0;
  usz        n  = stp_build(buf, sizeof(buf));
  CHECK(n != 0);
  usz off = 0;
  int ok  = 0;
  while (off < n) {
    usz used =
        quic_tparam_get_blob(wired_span_of(buf + off, n - off), &id, &found);
    if (!used) break;
    if (id == QUIC_TP_RESET_STREAM_AT && found.n == 0) ok = 1;
    off += used;
  }
  CHECK(ok);

  /* Hand-verified exact byte pair also occurs literally in the buffer. */
  int found_bytes = 0;
  for (usz i = 0; i + 1 < n; i++)
    if (buf[i] == 0x1d && buf[i + 1] == 0x00) found_bytes = 1;
  CHECK(found_bytes);
}

/* Regression: existing TPs are unaffected by adding reset_stream_at. */
static void test_server_tp_reset_stream_at_does_not_disturb_others(void) {
  u8  buf[256];
  u64 v;
  usz n = stp_build(buf, sizeof(buf));
  CHECK(n != 0);
  wired_span tp = wired_span_of(buf, n);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_DATA, &v) && v == 10000000);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v) && v == 100);
  CHECK(tp_int_value(buf, n, 0x20, &v) == 0); /* max_datagram_frame_size */
}

void test_server_tp(void) {
  test_server_tp_tunable_limits();
  test_server_tp_datagram_frame_size();
  test_server_tp_reset_stream_at_empty();
  test_server_tp_reset_stream_at_does_not_disturb_others();
  test_server_tp_ids_and_values();
  test_server_tp_retry_scid();
  test_server_tp_stateless_reset_token();
  test_server_tp_no_room();
  test_server_tp_parse_absent();
  test_client_tp_extract();
}
