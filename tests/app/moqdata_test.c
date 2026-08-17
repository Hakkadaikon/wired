#include "app/moqt/data/moqdata.h"

#include "moqt_golden.h"
#include "test.h"

/* @file
 * draft-ietf-moq-transport-19 data-plane tests, pinned to the shared golden
 * vectors (tests/app/moqt_golden.h, generated from
 * examples/moqt_chat/testvectors/moqt_golden.json).
 *
 * Test list:
 * - stream classification: 5 goldens (control/fetch/subgroup/padding/
 *   unknown); truncated input -> insufficient
 * - SUBGROUP_HEADER Type: 4 accept / 4 reject goldens; bit accessors pinned
 *   to the golden field values
 * - SUBGROUP_HEADER take: both golden streams; explicit Subgroup ID (mode
 *   0b10); deferred Subgroup ID (mode 0b01) + resolve; invalid Type ->
 *   violation; truncation -> insufficient
 * - SUBGROUP_HEADER put: both golden headers byte-exact; invalid Type ->
 *   violation; no room -> insufficient
 * - Object take: both golden streams end-to-end; Object ID delta chain;
 *   overflow boundary (wrap-free); Status 0x0/0x3/0x4 accepted, unknown ->
 *   violation; properties on non-Normal -> violation; properties skipped;
 *   truncation -> insufficient
 * - Object put + one-message builder: golden byte match; no room
 */

static int span_eq(wired_span a, const u8* p, usz n) {
  if (a.n != n) return 0;
  for (usz i = 0; i < n; i++)
    if (a.p[i] != p[i]) return 0;
  return 1;
}

static void check_classify(wired_span in, int kind, usz want_off) {
  usz off = 0;
  CHECK(moqdata_classify(in, &off) == kind);
  CHECK(off == want_off);
}

/* TEST: unidirectional stream type classification, all 5 goldens (3.4). */
static void test_moqdata_classify_golden(void) {
  check_classify(
      wired_span_of(
          g_moqt_data_stream_type_control, G_MOQT_DATA_STREAM_TYPE_CONTROL_LEN),
      QUIC_MOQDATA_STREAM_CONTROL, 2);
  check_classify(
      wired_span_of(
          g_moqt_data_stream_type_fetch, G_MOQT_DATA_STREAM_TYPE_FETCH_LEN),
      QUIC_MOQDATA_STREAM_FETCH, 1);
  check_classify(
      wired_span_of(
          g_moqt_data_stream_type_subgroup,
          G_MOQT_DATA_STREAM_TYPE_SUBGROUP_LEN),
      QUIC_MOQDATA_STREAM_SUBGROUP, 1);
  check_classify(
      wired_span_of(
          g_moqt_data_stream_type_padding, G_MOQT_DATA_STREAM_TYPE_PADDING_LEN),
      QUIC_MOQDATA_STREAM_PADDING, 5);
  check_classify(
      wired_span_of(
          g_moqt_data_stream_type_unknown, G_MOQT_DATA_STREAM_TYPE_UNKNOWN_LEN),
      QUIC_MOQDATA_STREAM_UNKNOWN, 1);
}

/* TEST: classification with a truncated type varint -> insufficient. */
static void test_moqdata_classify_truncated(void) {
  check_classify(wired_span_of(0, 0), QUIC_MOQDATA_STREAM_INSUFFICIENT, 0);
  /* first 2 bytes of the 5-byte padding type varint */
  check_classify(
      wired_span_of(g_moqt_data_stream_type_padding, 2),
      QUIC_MOQDATA_STREAM_INSUFFICIENT, 0);
}

/* TEST: Type accept/reject, the 8 golden values (11.4.2). */
static void test_moqdata_type_valid_golden(void) {
  CHECK(moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X10_TYPE));
  CHECK(moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X34_TYPE));
  CHECK(moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X59_TYPE));
  CHECK(moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X7B_TYPE));
  CHECK(!moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X20_NO_BIT4_TYPE));
  CHECK(!moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X0F_BELOW_RANGE_TYPE));
  CHECK(!moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X16_MODE3_TYPE));
  CHECK(!moqdata_type_valid(G_MOQT_DATA_SUBGROUP_TYPE_0X7E_MODE3_TYPE));
  /* boundary: bit7 set is outside 0b0XX1XXXX even with bit4 set */
  CHECK(!moqdata_type_valid(0x90));
}

/* TEST: Type bit accessors match the golden JSON field values. */
static void test_moqdata_type_bits_golden(void) {
  /* 0x10: everything off, mode 0b00 */
  CHECK(!moqdata_type_props(0x10));
  CHECK(moqdata_type_sgid_mode(0x10) == 0);
  CHECK(!moqdata_type_end_of_group(0x10));
  CHECK(!moqdata_type_default_priority(0x10));
  CHECK(!moqdata_type_first_object(0x10));
  /* 0x34: mode 0b10, default priority */
  CHECK(!moqdata_type_props(0x34));
  CHECK(moqdata_type_sgid_mode(0x34) == 2);
  CHECK(!moqdata_type_end_of_group(0x34));
  CHECK(moqdata_type_default_priority(0x34));
  CHECK(!moqdata_type_first_object(0x34));
  /* 0x59: properties, end of group, first object */
  CHECK(moqdata_type_props(0x59));
  CHECK(moqdata_type_sgid_mode(0x59) == 0);
  CHECK(moqdata_type_end_of_group(0x59));
  CHECK(!moqdata_type_default_priority(0x59));
  CHECK(moqdata_type_first_object(0x59));
  /* 0x7b: properties, mode 0b01, end of group, default prio, first */
  CHECK(moqdata_type_props(0x7b));
  CHECK(moqdata_type_sgid_mode(0x7b) == 1);
  CHECK(moqdata_type_end_of_group(0x7b));
  CHECK(moqdata_type_default_priority(0x7b));
  CHECK(moqdata_type_first_object(0x7b));
}

/* TEST: header of the basic golden stream (type 0x70, default priority,
 * mode 0b00). */
static void test_moqdata_subhdr_take_basic(void) {
  wired_span in = wired_span_of(
      g_moqt_data_subgroup_stream_basic, G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN);
  moqdata_subhdr h;
  usz            off = 0;
  CHECK(moqdata_subhdr_take(in, &off, &h) == QUIC_MOQDATA_OK);
  CHECK(off == 3);
  CHECK(h.type == 0x70);
  CHECK(h.track_alias == 1);
  CHECK(h.group_id == 0);
  CHECK(h.subgroup_id == 0);
  CHECK(!h.subgroup_id_pending);
  CHECK(moqdata_type_first_object(h.type));
  CHECK(moqdata_type_default_priority(h.type));
}

/* TEST: header of the status/end-of-group golden stream (type 0x18,
 * explicit priority 128). */
static void test_moqdata_subhdr_take_status_eog(void) {
  wired_span in = wired_span_of(
      g_moqt_data_subgroup_stream_status_eog,
      G_MOQT_DATA_SUBGROUP_STREAM_STATUS_EOG_LEN);
  moqdata_subhdr h;
  usz            off = 0;
  CHECK(moqdata_subhdr_take(in, &off, &h) == QUIC_MOQDATA_OK);
  CHECK(off == 4);
  CHECK(h.type == 0x18);
  CHECK(h.track_alias == 1);
  CHECK(h.group_id == 0);
  CHECK(h.priority == 128);
  CHECK(moqdata_type_end_of_group(h.type));
  CHECK(!moqdata_type_default_priority(h.type));
}

/* TEST: mode 0b10 carries an explicit Subgroup ID field. */
static void test_moqdata_subhdr_take_mode2(void) {
  static const u8 in[] = {0x14, 0x01, 0x02, 0x07, 0x2a};
  moqdata_subhdr  h;
  usz             off = 0;
  CHECK(
      moqdata_subhdr_take(wired_span_of(in, sizeof in), &off, &h) ==
      QUIC_MOQDATA_OK);
  CHECK(off == 5);
  CHECK(h.subgroup_id == 7);
  CHECK(!h.subgroup_id_pending);
  CHECK(h.priority == 0x2a);
}

/* TEST: mode 0b01 defers the Subgroup ID to the first Object ID. */
static void test_moqdata_subhdr_take_mode1_resolve(void) {
  static const u8 in[] = {0x12, 0x01, 0x02, 0x2a};
  moqdata_subhdr  h;
  usz             off = 0;
  CHECK(
      moqdata_subhdr_take(wired_span_of(in, sizeof in), &off, &h) ==
      QUIC_MOQDATA_OK);
  CHECK(off == 4);
  CHECK(h.subgroup_id_pending);
  moqdata_subhdr_resolve(&h, 5);
  CHECK(!h.subgroup_id_pending);
  CHECK(h.subgroup_id == 5);
  /* resolve on a non-pending header is a no-op */
  moqdata_subhdr_resolve(&h, 9);
  CHECK(h.subgroup_id == 5);
}

/* TEST: invalid Type on the wire -> violation, cursor untouched. */
static void test_moqdata_subhdr_take_bad_type(void) {
  static const u8 mode3[]  = {0x16, 0x01, 0x00};
  static const u8 nobit4[] = {0x20, 0x01, 0x00};
  moqdata_subhdr  h;
  usz             off = 0;
  CHECK(
      moqdata_subhdr_take(wired_span_of(mode3, sizeof mode3), &off, &h) ==
      QUIC_MOQDATA_VIOLATION);
  CHECK(
      moqdata_subhdr_take(wired_span_of(nobit4, sizeof nobit4), &off, &h) ==
      QUIC_MOQDATA_VIOLATION);
  CHECK(off == 0);
}

/* TEST: header cut short at every field -> insufficient, cursor untouched. */
static void test_moqdata_subhdr_take_truncated(void) {
  moqdata_subhdr h;
  for (usz n = 0; n < 3; n++) {
    usz off = 0;
    CHECK(
        moqdata_subhdr_take(
            wired_span_of(g_moqt_data_subgroup_stream_basic, n), &off, &h) ==
        QUIC_MOQDATA_INSUFFICIENT);
    CHECK(off == 0);
  }
  for (usz n = 0; n < 4; n++) {
    usz off = 0;
    CHECK(
        moqdata_subhdr_take(
            wired_span_of(g_moqt_data_subgroup_stream_status_eog, n), &off,
            &h) == QUIC_MOQDATA_INSUFFICIENT);
    CHECK(off == 0);
  }
}

/* TEST: header put reproduces both golden headers byte-exactly. */
static void test_moqdata_subhdr_put_golden(void) {
  u8             out[8];
  usz            off   = 0;
  moqdata_subhdr basic = {0};
  moqdata_subhdr eog   = {0};
  basic.type           = 0x70;
  basic.track_alias    = 1;
  eog.type             = 0x18;
  eog.track_alias      = 1;
  eog.priority         = 128;
  CHECK(
      moqdata_subhdr_put(wired_mspan_of(out, sizeof out), &off, &basic) ==
      QUIC_MOQDATA_OK);
  CHECK(span_eq(wired_span_of(out, off), g_moqt_data_subgroup_stream_basic, 3));
  off = 0;
  CHECK(
      moqdata_subhdr_put(wired_mspan_of(out, sizeof out), &off, &eog) ==
      QUIC_MOQDATA_OK);
  CHECK(span_eq(
      wired_span_of(out, off), g_moqt_data_subgroup_stream_status_eog, 4));
}

/* TEST: put rejects an invalid Type; reports no-room without advancing. */
static void test_moqdata_subhdr_put_errors(void) {
  u8             out[8];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x16; /* mode 0b11: reserved */
  CHECK(
      moqdata_subhdr_put(wired_mspan_of(out, sizeof out), &off, &h) ==
      QUIC_MOQDATA_VIOLATION);
  h.type = 0x18; /* needs 4 bytes, give 3 */
  CHECK(
      moqdata_subhdr_put(wired_mspan_of(out, 3), &off, &h) ==
      QUIC_MOQDATA_INSUFFICIENT);
  CHECK(off == 0);
}

/* TEST: the basic golden stream decodes to one Object: id 0, payload
 * "hi", Normal status (implicit for non-empty payload). */
static void test_moqdata_obj_take_basic_stream(void) {
  wired_span in = wired_span_of(
      g_moqt_data_subgroup_stream_basic, G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN);
  moqdata_subhdr h;
  moqdata_obj    o;
  usz            off = 0;
  CHECK(moqdata_subhdr_take(in, &off, &h) == QUIC_MOQDATA_OK);
  moqdata_objseq seq = moqdata_objseq_of(h.type);
  CHECK(moqdata_obj_take(in, &off, &seq, &o) == QUIC_MOQDATA_OK);
  CHECK(off == in.n);
  CHECK(o.object_id == 0);
  CHECK(o.status == 0);
  CHECK(span_eq(o.payload, (const u8*)"hi", 2));
}

/* TEST: the status/eog golden stream decodes to two Objects; the second
 * has Object ID prev+delta+1 = 1 and explicit EndOfGroup status 0x3. */
static void test_moqdata_obj_take_status_eog_stream(void) {
  wired_span in = wired_span_of(
      g_moqt_data_subgroup_stream_status_eog,
      G_MOQT_DATA_SUBGROUP_STREAM_STATUS_EOG_LEN);
  moqdata_subhdr h;
  moqdata_obj    o;
  usz            off = 0;
  CHECK(moqdata_subhdr_take(in, &off, &h) == QUIC_MOQDATA_OK);
  moqdata_objseq seq = moqdata_objseq_of(h.type);
  CHECK(moqdata_obj_take(in, &off, &seq, &o) == QUIC_MOQDATA_OK);
  CHECK(o.object_id == 0);
  CHECK(span_eq(o.payload, (const u8*)"hi", 2));
  CHECK(moqdata_obj_take(in, &off, &seq, &o) == QUIC_MOQDATA_OK);
  CHECK(off == in.n);
  CHECK(o.object_id == 1);
  CHECK(o.status == 0x3);
  CHECK(o.payload.n == 0);
}

/* TEST: Object ID delta chain: first = delta, then prev + delta + 1. */
static void test_moqdata_obj_take_delta_chain(void) {
  static const u8 in[] = {0x05, 0x01, 0x41, 0x02, 0x01, 0x42};
  moqdata_objseq  seq  = moqdata_objseq_of(0x10);
  moqdata_obj     o;
  usz             off = 0;
  wired_span      s   = wired_span_of(in, sizeof in);
  CHECK(moqdata_obj_take(s, &off, &seq, &o) == QUIC_MOQDATA_OK);
  CHECK(o.object_id == 5);
  CHECK(moqdata_obj_take(s, &off, &seq, &o) == QUIC_MOQDATA_OK);
  CHECK(o.object_id == 8);
  CHECK(off == sizeof in);
}

/* TEST: cumulative Object ID overflow -> violation, checked without u64
 * wrap; the exact 2^64-1 boundary is still accepted. */
static void test_moqdata_obj_take_id_overflow(void) {
  /* delta 0, payload length 0, explicit Normal status */
  static const u8 one[] = {0x00, 0x00, 0x00};
  wired_span      s     = wired_span_of(one, sizeof one);
  moqdata_obj     o;
  moqdata_objseq  seq = moqdata_objseq_of(0x10);
  usz             off = 0;
  seq.have_prev       = 1;
  seq.prev_id         = (u64)-1 - 1; /* 2^64-2: +0+1 lands exactly on max */
  CHECK(moqdata_obj_take(s, &off, &seq, &o) == QUIC_MOQDATA_OK);
  CHECK(o.object_id == (u64)-1);
  off = 0;
  CHECK(moqdata_obj_take(s, &off, &seq, &o) == QUIC_MOQDATA_VIOLATION);
  CHECK(off == 0);
  /* first object: delta alone may be 2^64-1 (no +1 applied) */
  static const u8 max[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                           0xff, 0xff, 0xff, 0x00, 0x00};
  moqdata_objseq  fresh = moqdata_objseq_of(0x10);
  off                   = 0;
  CHECK(
      moqdata_obj_take(wired_span_of(max, sizeof max), &off, &fresh, &o) ==
      QUIC_MOQDATA_OK);
  CHECK(o.object_id == (u64)-1);
}

/* TEST: Status 0x0/0x3/0x4 accepted; unknown values -> violation. */
static void test_moqdata_obj_take_status_values(void) {
  static const u8 normal[] = {0x00, 0x00, 0x00};
  static const u8 eot[]    = {0x00, 0x00, 0x04};
  static const u8 bad1[]   = {0x00, 0x00, 0x01};
  static const u8 bad5[]   = {0x00, 0x00, 0x05};
  moqdata_obj     o;
  usz             off;
  moqdata_objseq  seq;
  seq = moqdata_objseq_of(0x10);
  off = 0;
  CHECK(
      moqdata_obj_take(wired_span_of(normal, 3), &off, &seq, &o) ==
      QUIC_MOQDATA_OK);
  CHECK(o.status == 0x0);
  seq = moqdata_objseq_of(0x10);
  off = 0;
  CHECK(
      moqdata_obj_take(wired_span_of(eot, 3), &off, &seq, &o) ==
      QUIC_MOQDATA_OK);
  CHECK(o.status == 0x4);
  seq = moqdata_objseq_of(0x10);
  off = 0;
  CHECK(
      moqdata_obj_take(wired_span_of(bad1, 3), &off, &seq, &o) ==
      QUIC_MOQDATA_VIOLATION);
  CHECK(off == 0);
  seq = moqdata_objseq_of(0x10);
  off = 0;
  CHECK(
      moqdata_obj_take(wired_span_of(bad5, 3), &off, &seq, &o) ==
      QUIC_MOQDATA_VIOLATION);
}

/* TEST: PROPERTIES bit set: Properties Length is read and skipped; a
 * non-empty Properties on a non-Normal Object -> violation; an empty one
 * is allowed. */
static void test_moqdata_obj_take_properties(void) {
  /* delta 0, props len 2 (skipped), payload len 1, 'X' */
  static const u8 props_ok[] = {0x00, 0x02, 0xaa, 0xbb, 0x01, 0x58};
  /* delta 0, props len 2, payload len 0, status EndOfGroup */
  static const u8 props_eog[] = {0x00, 0x02, 0xaa, 0xbb, 0x00, 0x03};
  /* delta 0, props len 0, payload len 0, status EndOfGroup */
  static const u8 empty_eog[] = {0x00, 0x00, 0x00, 0x03};
  moqdata_obj     o;
  usz             off;
  moqdata_objseq  seq;
  seq = moqdata_objseq_of(0x11); /* PROPERTIES bit set */
  CHECK(seq.has_props);
  off = 0;
  CHECK(
      moqdata_obj_take(
          wired_span_of(props_ok, sizeof props_ok), &off, &seq, &o) ==
      QUIC_MOQDATA_OK);
  CHECK(off == sizeof props_ok);
  CHECK(span_eq(o.payload, (const u8*)"X", 1));
  seq = moqdata_objseq_of(0x11);
  off = 0;
  CHECK(
      moqdata_obj_take(
          wired_span_of(props_eog, sizeof props_eog), &off, &seq, &o) ==
      QUIC_MOQDATA_VIOLATION);
  seq = moqdata_objseq_of(0x11);
  off = 0;
  CHECK(
      moqdata_obj_take(
          wired_span_of(empty_eog, sizeof empty_eog), &off, &seq, &o) ==
      QUIC_MOQDATA_OK);
  CHECK(o.status == 0x3);
}

/* TEST: input ending mid-Object -> insufficient, cursor untouched. */
static void test_moqdata_obj_take_truncated(void) {
  moqdata_obj o;
  /* basic golden stream cut inside the object (header is 3 bytes) */
  for (usz n = 3; n < G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN; n++) {
    moqdata_objseq seq = moqdata_objseq_of(0x70);
    usz            off = 3;
    CHECK(
        moqdata_obj_take(
            wired_span_of(g_moqt_data_subgroup_stream_basic, n), &off, &seq,
            &o) == QUIC_MOQDATA_INSUFFICIENT);
    CHECK(off == 3);
    CHECK(!seq.have_prev);
  }
  /* zero payload length but the status varint is missing */
  static const u8 nostatus[] = {0x00, 0x00};
  moqdata_objseq  seq        = moqdata_objseq_of(0x10);
  usz             off        = 0;
  CHECK(
      moqdata_obj_take(
          wired_span_of(nostatus, sizeof nostatus), &off, &seq, &o) ==
      QUIC_MOQDATA_INSUFFICIENT);
  /* PROPERTIES bit set but the length varint is missing */
  static const u8 onlydelta[] = {0x00};
  moqdata_objseq  pseq        = moqdata_objseq_of(0x11);
  off                         = 0;
  CHECK(
      moqdata_obj_take(
          wired_span_of(onlydelta, sizeof onlydelta), &off, &pseq, &o) ==
      QUIC_MOQDATA_INSUFFICIENT);
}

/* TEST: Object put: payload form, explicit-Normal empty form, status
 * form; no room -> insufficient without advancing. */
static void test_moqdata_obj_put(void) {
  static const u8 want_pay[]    = {0x00, 0x02, 0x68, 0x69};
  static const u8 want_empty[]  = {0x00, 0x00, 0x00};
  static const u8 want_status[] = {0x00, 0x00, 0x03};
  u8              out[8];
  usz             off = 0;
  CHECK(
      moqdata_obj_put(
          wired_mspan_of(out, sizeof out), &off, 0,
          wired_span_of((const u8*)"hi", 2)) == QUIC_MOQDATA_OK);
  CHECK(span_eq(wired_span_of(out, off), want_pay, sizeof want_pay));
  off = 0;
  CHECK(
      moqdata_obj_put(
          wired_mspan_of(out, sizeof out), &off, 0, wired_span_of(0, 0)) ==
      QUIC_MOQDATA_OK);
  CHECK(span_eq(wired_span_of(out, off), want_empty, sizeof want_empty));
  off = 0;
  CHECK(
      moqdata_obj_put_status(wired_mspan_of(out, sizeof out), &off, 0, 0x3) ==
      QUIC_MOQDATA_OK);
  CHECK(span_eq(wired_span_of(out, off), want_status, sizeof want_status));
  off = 0;
  CHECK(
      moqdata_obj_put(
          wired_mspan_of(out, 3), &off, 0, wired_span_of((const u8*)"hi", 2)) ==
      QUIC_MOQDATA_INSUFFICIENT);
  CHECK(off == 0);
}

/* TEST: the one-message builder reproduces the basic golden stream. */
static void test_moqdata_msg_build_golden(void) {
  u8          out[QUIC_MOQDATA_MSG_OVERHEAD + 2];
  usz         off = 0;
  moqdata_msg m   = {1, 0, {(const u8*)"hi", 2}};
  CHECK(
      moqdata_msg_build(wired_mspan_of(out, sizeof out), &off, &m) ==
      QUIC_MOQDATA_OK);
  CHECK(span_eq(
      wired_span_of(out, off), g_moqt_data_subgroup_stream_basic,
      G_MOQT_DATA_SUBGROUP_STREAM_BASIC_LEN));
}

/* TEST: worst-case varints fit in QUIC_MOQDATA_MSG_OVERHEAD; a too-small
 * buffer -> insufficient without advancing. */
static void test_moqdata_msg_build_bounds(void) {
  u8          out[QUIC_MOQDATA_MSG_OVERHEAD];
  usz         off = 0;
  moqdata_msg m   = {(u64)-1, (u64)-1, {0, 0}};
  CHECK(
      moqdata_msg_build(wired_mspan_of(out, sizeof out), &off, &m) ==
      QUIC_MOQDATA_OK);
  off            = 0;
  moqdata_msg hi = {1, 0, {(const u8*)"hi", 2}};
  CHECK(
      moqdata_msg_build(wired_mspan_of(out, 6), &off, &hi) ==
      QUIC_MOQDATA_INSUFFICIENT);
  CHECK(off == 0);
}

/* TEST: the status/eog golden stream is reproduced by the put path
 * (header + payload object + status object). */
static void test_moqdata_put_path_status_eog_golden(void) {
  u8             out[16];
  usz            off = 0;
  moqdata_subhdr h   = {0};
  h.type             = 0x18;
  h.track_alias      = 1;
  h.priority         = 128;
  CHECK(
      moqdata_subhdr_put(wired_mspan_of(out, sizeof out), &off, &h) ==
      QUIC_MOQDATA_OK);
  CHECK(
      moqdata_obj_put(
          wired_mspan_of(out, sizeof out), &off, 0,
          wired_span_of((const u8*)"hi", 2)) == QUIC_MOQDATA_OK);
  CHECK(
      moqdata_obj_put_status(wired_mspan_of(out, sizeof out), &off, 0, 0x3) ==
      QUIC_MOQDATA_OK);
  CHECK(span_eq(
      wired_span_of(out, off), g_moqt_data_subgroup_stream_status_eog,
      G_MOQT_DATA_SUBGROUP_STREAM_STATUS_EOG_LEN));
}

void test_moqdata(void) {
  test_moqdata_classify_golden();
  test_moqdata_classify_truncated();
  test_moqdata_type_valid_golden();
  test_moqdata_type_bits_golden();
  test_moqdata_subhdr_take_basic();
  test_moqdata_subhdr_take_status_eog();
  test_moqdata_subhdr_take_mode2();
  test_moqdata_subhdr_take_mode1_resolve();
  test_moqdata_subhdr_take_bad_type();
  test_moqdata_subhdr_take_truncated();
  test_moqdata_subhdr_put_golden();
  test_moqdata_subhdr_put_errors();
  test_moqdata_obj_take_basic_stream();
  test_moqdata_obj_take_status_eog_stream();
  test_moqdata_obj_take_delta_chain();
  test_moqdata_obj_take_id_overflow();
  test_moqdata_obj_take_status_values();
  test_moqdata_obj_take_properties();
  test_moqdata_obj_take_truncated();
  test_moqdata_obj_put();
  test_moqdata_msg_build_golden();
  test_moqdata_msg_build_bounds();
  test_moqdata_put_path_status_eog_golden();
}
