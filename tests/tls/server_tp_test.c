#include "test.h"

/* RFC 9000 18.2. The DCID/SCID the build is told to advertise. */
static const u8 odcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
static const u8 scid[]  = {0x11, 0x22, 0x33, 0x44, 0x55};

/* Build server TPs for (odcid, scid) into buf; returns the encoded length. */
static usz stp_build(u8 *buf, usz cap) {
  quic_obuf ob = quic_obuf_of(buf, cap);
  quic_span od = quic_span_of(odcid, sizeof(odcid));
  quic_span sc = quic_span_of(scid, sizeof(scid));
  return quic_stp_build_server(od, sc, &ob) ? ob.len : 0;
}

/* quic_stp_parse for an integer-valued parameter, discarding the bytes view.
 */
static int parse_int(quic_span tp, u64 param_id, u64 *v) {
  quic_stp_out out = {v, 0};
  return quic_stp_parse(tp, param_id, &out);
}

/* Append one integer TP at ob->len (mirrors stp/server_tp.c's put_int). */
static int put_int_at(quic_obuf *ob, u64 id, u64 val) {
  quic_obuf tail = quic_obuf_of(ob->p + ob->len, ob->cap - ob->len);
  usz       w    = quic_tparam_put_int(&tail, id, val);
  ob->len += w;
  return w != 0;
}

static void test_server_tp_ids_and_values(void) {
  u8           buf[256];
  u64          v;
  quic_span    b;
  quic_stp_out bo = {0, &b};
  usz          n  = stp_build(buf, sizeof(buf));
  CHECK(n != 0);
  quic_span tp = quic_span_of(buf, n);

  /* RFC 9000 7.3: original_destination_connection_id carries the client DCID.
   */
  CHECK(
      quic_stp_parse(tp, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, &bo) == 1);
  CHECK(
      b.n == sizeof(odcid) &&
      quic_tparam_cid_match(b, quic_span_of(odcid, sizeof(odcid))));

  /* RFC 9000 7.3: initial_source_connection_id carries the server SCID. */
  CHECK(quic_stp_parse(tp, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, &bo) == 1);
  CHECK(
      b.n == sizeof(scid) &&
      quic_tparam_cid_match(b, quic_span_of(scid, sizeof(scid))));

  CHECK(parse_int(tp, QUIC_TP_MAX_IDLE_TIMEOUT, &v) && v == 30000);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_DATA, &v) && v == 1048576);
  CHECK(
      parse_int(tp, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, &v) &&
      v == 262144);
  CHECK(
      parse_int(tp, QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, &v) &&
      v == 262144);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, &v) && v == 262144);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v) && v == 100);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_UNI, &v) && v == 100);
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
      parse_int(quic_span_of(buf, n), QUIC_TP_STATELESS_RESET_TOKEN, &v) == 0);
  CHECK(v == 7);
}

/* A client's transport parameters, parsed for the values the server needs. */
static void test_client_tp_extract(void) {
  u8        buf[64];
  u64       v;
  quic_obuf ob = quic_obuf_of(buf, sizeof(buf));
  CHECK(put_int_at(&ob, QUIC_TP_INITIAL_MAX_DATA, 49152));
  CHECK(put_int_at(&ob, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 3));
  quic_span tp = quic_span_of(buf, ob.len);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_DATA, &v) && v == 49152);
  CHECK(parse_int(tp, QUIC_TP_INITIAL_MAX_STREAMS_BIDI, &v) && v == 3);
}

void test_server_tp(void) {
  test_server_tp_ids_and_values();
  test_server_tp_no_room();
  test_server_tp_parse_absent();
  test_client_tp_extract();
}
