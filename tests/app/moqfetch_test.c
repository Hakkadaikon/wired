#include "app/moqt/fetch/moqfetch.h"

#include "app/moqt/vi/moqvi.h"
#include "moqt_golden.h"
#include "test.h"

/* draft-ietf-moq-transport-19 FETCH (10.12), FETCH_OK (10.13) and the
 * fetch data stream (11.4.4). Wire bytes for the round trips come from
 * tests/app/moqt_golden.h; the rejection cases pin single fields. */

/* Frames a golden message with moqctl_peek_type and returns its body. */
static wired_span moqfetch_t_body(const u8* msg, usz n, u64 want_type) {
  usz        off  = 0;
  u64        type = 0;
  wired_span body = wired_span_of(msg, 0);
  CHECK(
      moqctl_peek_type(wired_span_of(msg, n), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(type == want_type);
  CHECK(off == n);
  return body;
}

static void moqfetch_t_same(const u8* out, usz n, wired_span want) {
  CHECK(n == want.n);
  for (usz i = 0; i < n && i < want.n; i++) CHECK(out[i] == want.p[i]);
}

static int moqfetch_t_reencode(const moqfetch_fetch* m, wired_span want) {
  u8  out[MOQCTL_MAX_MSG_LEN];
  usz n = 0;
  if (!moqfetch_fetch_encode(wired_mspan_of(out, sizeof out), &n, m)) return 0;
  moqfetch_t_same(out, n, want);
  return 1;
}

static void test_moqfetch_standalone_golden(void) {
  wired_span body = moqfetch_t_body(
      g_moqt_ctl_fetch_standalone, G_MOQT_CTL_FETCH_STANDALONE_LEN,
      MOQFETCH_T_FETCH);
  moqfetch_fetch m;
  if (moqfetch_fetch_take(body, &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.request_id == 0);
  CHECK(m.fetch_type == MOQFETCH_STANDALONE);
  CHECK(m.track.ns.n == 1);
  CHECK(m.track.ns.fields[0].p[0] == 'a');
  CHECK(m.track.name.n == 1);
  CHECK(m.track.name.p[0] == 'b');
  CHECK(m.start.group == 0 && m.start.object == 0);
  CHECK(m.end.group == 1 && m.end.object == 0);
  CHECK(m.params.n == 0);
  CHECK(moqfetch_t_reencode(&m, body));
}

static void test_moqfetch_joining_golden(void) {
  wired_span rel = moqfetch_t_body(
      g_moqt_ctl_fetch_relative_joining, G_MOQT_CTL_FETCH_RELATIVE_JOINING_LEN,
      MOQFETCH_T_FETCH);
  wired_span abs = moqfetch_t_body(
      g_moqt_ctl_fetch_absolute_joining, G_MOQT_CTL_FETCH_ABSOLUTE_JOINING_LEN,
      MOQFETCH_T_FETCH);
  moqfetch_fetch m;
  CHECK(moqfetch_fetch_take(rel, &m) == MOQCTL_OK);
  CHECK(m.request_id == 2);
  CHECK(m.fetch_type == MOQFETCH_RELATIVE_JOINING);
  CHECK(m.joining_request_id == 0 && m.joining_start == 1);
  CHECK(moqfetch_t_reencode(&m, rel));
  CHECK(moqfetch_fetch_take(abs, &m) == MOQCTL_OK);
  CHECK(m.request_id == 4);
  CHECK(m.fetch_type == MOQFETCH_ABSOLUTE_JOINING);
  CHECK(m.joining_request_id == 0 && m.joining_start == 5);
  CHECK(m.params.n == 1);
  CHECK(m.params.items[0].type == MOQCTL_PARAM_SUBSCRIBER_PRIORITY);
  CHECK(m.params.items[0].u8v == 128);
  CHECK(moqfetch_t_reencode(&m, abs));
}

/* 10.12: "a Fetch Type other than 0x1, 0x2 or 0x3 MUST close the session
 * with a PROTOCOL_VIOLATION"; FORWARD is not a FETCH parameter
 * (10.2.17). */
static void test_moqfetch_bad_type_and_scope(void) {
  static const u8 t0[]  = {0x00, 0x00, 0x00, 0x00, 0x00};
  static const u8 t4[]  = {0x00, 0x04, 0x00, 0x00, 0x00};
  static const u8 fwd[] = {0x00, 0x02, 0x00, 0x00, 0x01, 0x10, 0x01};
  moqfetch_fetch  m     = {0};
  u8              out[16];
  usz             n = 0;
  CHECK(
      moqfetch_fetch_take(wired_span_of(t0, sizeof t0), &m) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqfetch_fetch_take(wired_span_of(t4, sizeof t4), &m) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqfetch_fetch_take(wired_span_of(fwd, sizeof fwd), &m) ==
      MOQCTL_VIOLATION);
  m.fetch_type = 4;
  CHECK(!moqfetch_fetch_encode(wired_mspan_of(out, sizeof out), &n, &m));
}

static void moqfetch_t_mismatch(const u8* msg, usz msg_len) {
  const u8*      b = msg + 3;
  usz            n = msg_len - 3;
  u8             extra[32];
  moqfetch_fetch m;
  for (usz cut = 0; cut < n; cut++)
    CHECK(moqfetch_fetch_take(wired_span_of(b, cut), &m) == MOQCTL_VIOLATION);
  for (usz i = 0; i < n; i++) extra[i] = b[i];
  extra[n] = 0;
  CHECK(
      moqfetch_fetch_take(wired_span_of(extra, n + 1), &m) == MOQCTL_VIOLATION);
}

static void test_moqfetch_length_mismatch(void) {
  moqfetch_t_mismatch(
      g_moqt_ctl_fetch_standalone, G_MOQT_CTL_FETCH_STANDALONE_LEN);
  moqfetch_t_mismatch(
      g_moqt_ctl_fetch_absolute_joining, G_MOQT_CTL_FETCH_ABSOLUTE_JOINING_LEN);
}

/* 1.4.1 MOQT varint size boundaries on Joining Start: 127 | 128 and
 * 16383 | 16384 round trip with minimal size. */
static void moqfetch_t_js(u64 js, usz want_len) {
  moqfetch_fetch m = {0};
  moqfetch_fetch d;
  u8             out[32];
  usz            n = 0;
  m.fetch_type     = MOQFETCH_ABSOLUTE_JOINING;
  m.joining_start  = js;
  CHECK(moqfetch_fetch_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(n == 4 + want_len);
  CHECK(moqfetch_fetch_take(wired_span_of(out, n), &d) == MOQCTL_OK);
  CHECK(d.joining_start == js);
}

static void test_moqfetch_varint_boundaries(void) {
  moqfetch_t_js(127, 1);
  moqfetch_t_js(128, 2);
  moqfetch_t_js(16383, 2);
  moqfetch_t_js(16384, 3);
}

static void test_moqfetch_ok_golden(void) {
  wired_span body = moqfetch_t_body(
      g_moqt_ctl_fetch_ok_basic, G_MOQT_CTL_FETCH_OK_BASIC_LEN,
      MOQFETCH_T_FETCH_OK);
  moqfetch_ok m;
  u8          out[MOQCTL_MAX_MSG_LEN];
  usz         n = 0;
  if (moqfetch_ok_take(body, &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.end_of_track == 1);
  CHECK(m.end.group == 3 && m.end.object == 5);
  CHECK(m.params.n == 0);
  CHECK(m.track_properties.n == 0);
  CHECK(moqfetch_ok_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqfetch_t_same(out, n, body);
}

/* FETCH_OK: truncation inside the fixed fields is a Length mismatch, the
 * rest after the parameters is Track Properties, and FORWARD is out of
 * the FETCH_OK scope. */
static void test_moqfetch_ok_reject(void) {
  static const u8 props[] = {0x00, 0x01, 0x01, 0x00, 0x0e, 0x40};
  static const u8 fwd[]   = {0x00, 0x01, 0x01, 0x01, 0x10, 0x01};
  const u8*       b       = g_moqt_ctl_fetch_ok_basic + 3;
  moqfetch_ok     m;
  for (usz cut = 0; cut < G_MOQT_CTL_FETCH_OK_BASIC_MSG_LEN; cut++)
    CHECK(moqfetch_ok_take(wired_span_of(b, cut), &m) == MOQCTL_VIOLATION);
  CHECK(moqfetch_ok_take(wired_span_of(props, sizeof props), &m) == MOQCTL_OK);
  CHECK(m.end_of_track == 0);
  CHECK(m.track_properties.n == 2);
  CHECK(
      moqfetch_ok_take(wired_span_of(fwd, sizeof fwd), &m) == MOQCTL_VIOLATION);
}

/* 11.4.4 Figure 26: FETCH_HEADER is Type 0x5 + Request ID. */
static void test_moqfetch_hdr(void) {
  static const u8 sub[] = {0x10, 0x00};
  u8              out[16];
  usz             n   = 0;
  usz             off = 0;
  u64             rid = 0;
  CHECK(moqfetch_hdr_put(wired_mspan_of(out, sizeof out), &n, 16384));
  CHECK(n == 4);
  CHECK(
      moqfetch_hdr_take(wired_span_of(out, 3), &off, &rid) ==
      MOQCTL_INSUFFICIENT);
  CHECK(off == 0);
  CHECK(moqfetch_hdr_take(wired_span_of(out, n), &off, &rid) == MOQCTL_OK);
  CHECK(off == n && rid == 16384);
  off = 0;
  CHECK(
      moqfetch_hdr_take(wired_span_of(sub, sizeof sub), &off, &rid) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqfetch_hdr_take(wired_span_of(sub, 0), &off, &rid) ==
      MOQCTL_INSUFFICIENT);
}

/* Decodes every Object of a golden fetch stream into objs, then re-encodes
 * them with a fresh sequence and expects the same bytes. */
static usz moqfetch_t_stream(
    const u8* s, usz len, u64 want_rid, moqfetch_obj* objs, usz cap) {
  wired_span   in  = wired_span_of(s, len);
  usz          off = 0;
  usz          k   = 0;
  u64          rid = 99;
  moqfetch_seq seq = {0};
  moqfetch_seq enc = {0};
  u8           out[64];
  usz          n = 0;
  CHECK(moqfetch_hdr_take(in, &off, &rid) == MOQCTL_OK);
  CHECK(rid == want_rid);
  while (k < cap && moqfetch_obj_take(in, &off, &seq, &objs[k]) == MOQCTL_OK)
    k++;
  CHECK(off == len);
  CHECK(moqfetch_hdr_put(wired_mspan_of(out, sizeof out), &n, rid));
  for (usz i = 0; i < k; i++)
    CHECK(
        moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &enc, &objs[i]));
  moqfetch_t_same(out, n, in);
  return k;
}

static void test_moqfetch_stream_golden(void) {
  moqfetch_obj o[4];
  usz          k = moqfetch_t_stream(
      g_moqt_data_fetch_stream_basic, G_MOQT_DATA_FETCH_STREAM_BASIC_LEN, 0, o,
      4);
  CHECK(k == 2);
  if (k != 2) return;
  CHECK(o[0].group == 5 && o[0].object == 0);
  CHECK(o[0].has_subgroup && o[0].subgroup == 0);
  CHECK(o[0].priority == 0x80);
  CHECK(o[0].payload.n == 2 && o[0].payload.p[0] == 'h');
  CHECK(o[1].group == 5 && o[1].object == 1);
  CHECK(o[1].has_subgroup && o[1].subgroup == 0);
  CHECK(o[1].priority == 0x80);
  CHECK(o[1].payload.n == 1 && o[1].payload.p[0] == 'x');
}

/* 11.4.4.2: End of Range markers carry the range end only and set the
 * prior Group/Object; Subgroup and Priority come from real Objects. */
static void test_moqfetch_stream_end_of_range(void) {
  moqfetch_obj o[4];
  usz          k = moqfetch_t_stream(
      g_moqt_data_fetch_stream_end_of_range,
      G_MOQT_DATA_FETCH_STREAM_END_OF_RANGE_LEN, 1, o, 4);
  CHECK(k == 3);
  if (k != 3) return;
  CHECK(o[0].flags == MOQFETCH_EOR_NONEXISTENT);
  CHECK(o[0].group == 2 && o[0].object == 3);
  CHECK(!o[0].has_subgroup && o[0].payload.n == 0);
  CHECK(o[1].group == 2 && o[1].object == 4);
  CHECK(o[1].has_subgroup && o[1].subgroup == 0);
  CHECK(o[1].priority == 0x40 && o[1].payload.n == 0);
  CHECK(o[2].flags == MOQFETCH_EOR_UNKNOWN);
  CHECK(o[2].group == 3 && o[2].object == 7);
}

/* draft-22 SS11.4.1: End of Timed-Out Range 0x20C (wire 82 0C) carries
 * Group and Object like the other markers; only a sequence that allows it
 * (a draft-22 stream) takes it, draft-19's 11.4.4 rejects it. */
static void test_moqfetch_eor_timed_out(void) {
  static const u8 wire[] = {0x82, 0x0C, 0x03, 0x04};
  moqfetch_seq    seq    = {0};
  moqfetch_obj    o;
  u8              out[8];
  usz             off = 0, n = 0;
  CHECK(
      moqfetch_obj_take(wired_span_of(wire, sizeof wire), &off, &seq, &o) ==
      MOQCTL_VIOLATION);
  seq.eor_timed_out = 1;
  CHECK(
      moqfetch_obj_take(wired_span_of(wire, sizeof wire), &off, &seq, &o) ==
      MOQCTL_OK);
  CHECK(o.flags == MOQFETCH_EOR_TIMED_OUT && o.group == 3 && o.object == 4);
  seq = (moqfetch_seq){0};
  CHECK(!moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &seq, &o));
  seq.eor_timed_out = 1;
  n                 = 0;
  CHECK(moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &seq, &o));
  CHECK(n == sizeof wire);
  for (usz i = 0; i < n; i++) CHECK(out[i] == wire[i]);
}

/* Runs one Object decode from a fresh (or given) sequence. */
static int moqfetch_t_one(
    const u8* b, usz n, moqfetch_seq* seq, moqfetch_obj* o) {
  usz off = 0;
  return moqfetch_obj_take(wired_span_of(b, n), &off, seq, o);
}

/* 11.4.4: values >= 128 other than 0x8C / 0x10C are violations; the first
 * Object must carry Group and Object deltas and may not reference a prior
 * Subgroup or Priority. */
static void test_moqfetch_obj_flags_reject(void) {
  static const u8 f80[]    = {0x80, 0x80, 0x00, 0x00, 0x00};
  static const u8 f8d[]    = {0x80, 0x8d, 0x00, 0x00, 0x00};
  static const u8 no_g[]   = {0x14, 0x00, 0x00, 0x00};
  static const u8 no_o[]   = {0x18, 0x00, 0x00, 0x00};
  static const u8 sg1[]    = {0x1d, 0x00, 0x00, 0x00, 0x00};
  static const u8 sg2[]    = {0x1e, 0x00, 0x00, 0x00, 0x00};
  static const u8 noprio[] = {0x0c, 0x00, 0x00, 0x00};
  moqfetch_seq    seq      = {0};
  moqfetch_obj    o;
  CHECK(moqfetch_t_one(f80, sizeof f80, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(f8d, sizeof f8d, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(no_g, sizeof no_g, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(no_o, sizeof no_o, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(sg1, sizeof sg1, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(sg2, sizeof sg2, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(noprio, sizeof noprio, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(!seq.have_loc);
}

/* 11.4.4.2: after an End of Range with no real Object before it, a flag
 * referencing the prior Subgroup or Priority is a violation. */
static void test_moqfetch_obj_after_eor_reject(void) {
  static const u8 eor[]    = {0x80, 0x8c, 0x02, 0x03};
  static const u8 sg1[]    = {0x11, 0x40, 0x00};
  static const u8 sg2[]    = {0x12, 0x40, 0x00};
  static const u8 noprio[] = {0x00, 0x00};
  static const u8 cut[]    = {0x10};
  moqfetch_seq    seq      = {0};
  moqfetch_obj    o;
  CHECK(moqfetch_t_one(eor, sizeof eor, &seq, &o) == MOQCTL_OK);
  CHECK(moqfetch_t_one(sg1, sizeof sg1, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(sg2, sizeof sg2, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(noprio, sizeof noprio, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(cut, sizeof cut, &seq, &o) == MOQCTL_INSUFFICIENT);
}

/* 11.4.4.1 Table 8 subgroup modes, the Datagram flag (no Subgroup ID,
 * the two LSBs ignored) and Properties. */
static void test_moqfetch_obj_subgroup_modes(void) {
  /* first: sg field 7, prio 1, props {0e 40}, payload "a" */
  static const u8 first[] = {0x3f, 0x01, 0x07, 0x00, 0x01,
                             0x02, 0x0e, 0x40, 0x01, 'a'};
  static const u8 plus1[] = {0x02, 0x00};
  static const u8 same[]  = {0x01, 0x00};
  static const u8 dgram[] = {0x43, 0x00};
  moqfetch_seq    seq     = {0};
  moqfetch_obj    o;
  CHECK(moqfetch_t_one(first, sizeof first, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 1 && o.object == 0 && o.subgroup == 7);
  CHECK(o.priority == 1 && o.has_props && o.props.n == 2);
  CHECK(o.payload.n == 1);
  CHECK(moqfetch_t_one(plus1, sizeof plus1, &seq, &o) == MOQCTL_OK);
  CHECK(o.subgroup == 8 && o.object == 1 && !o.has_props);
  CHECK(moqfetch_t_one(same, sizeof same, &seq, &o) == MOQCTL_OK);
  CHECK(o.subgroup == 8 && o.object == 2 && o.priority == 1);
  CHECK(moqfetch_t_one(dgram, sizeof dgram, &seq, &o) == MOQCTL_OK);
  CHECK(!o.has_subgroup && o.object == 3);
}

/* 11.4.4.1: Group ID Delta ascending -> prior + (Delta + 1), descending ->
 * prior - (Delta + 1), outside 0..2^64-1 a violation; Object ID with no
 * Group ID Delta -> prior + Object ID Delta. */
static void test_moqfetch_obj_group_order(void) {
  static const u8 first[] = {0x1c, 0x05, 0x02, 0x00, 0x00};
  static const u8 g_d0[]  = {0x08, 0x00, 0x00};
  static const u8 g_d3[]  = {0x08, 0x03, 0x00};
  static const u8 o_d3[]  = {0x04, 0x03, 0x00};
  moqfetch_seq    seq     = {0};
  moqfetch_obj    o;
  CHECK(moqfetch_t_one(first, sizeof first, &seq, &o) == MOQCTL_OK);
  CHECK(moqfetch_t_one(o_d3, sizeof o_d3, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 5 && o.object == 5);
  CHECK(moqfetch_t_one(g_d0, sizeof g_d0, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 6 && o.object == 6);
  seq            = (moqfetch_seq){0};
  seq.descending = 1;
  CHECK(moqfetch_t_one(first, sizeof first, &seq, &o) == MOQCTL_OK);
  CHECK(moqfetch_t_one(g_d0, sizeof g_d0, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 4);
  CHECK(moqfetch_t_one(g_d3, sizeof g_d3, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == 0);
  CHECK(moqfetch_t_one(g_d0, sizeof g_d0, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(seq.group == 0);
}

/* 11.4.4.1: Group or Object ID above 2^64-1 is a violation. */
static void test_moqfetch_obj_overflow(void) {
  u8              max_first[32];
  wired_mspan     m        = wired_mspan_of(max_first, sizeof max_first);
  usz             n        = 0;
  static const u8 next_g[] = {0x08, 0x00, 0x00};
  static const u8 next_o[] = {0x00, 0x00};
  moqfetch_seq    seq      = {0};
  moqfetch_obj    o;
  max_first[n++] = 0x1c;
  CHECK(moqvi_put(m, &n, ~0ULL));
  CHECK(moqvi_put(m, &n, ~0ULL));
  max_first[n++] = 0;
  max_first[n++] = 0;
  CHECK(moqfetch_t_one(max_first, n, &seq, &o) == MOQCTL_OK);
  CHECK(o.group == ~0ULL && o.object == ~0ULL);
  CHECK(moqfetch_t_one(next_g, sizeof next_g, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(next_o, sizeof next_o, &seq, &o) == MOQCTL_VIOLATION);
}

/* Truncated Objects need more stream bytes: INSUFFICIENT, nothing moved. */
static void test_moqfetch_obj_truncated(void) {
  const u8*    b   = g_moqt_data_fetch_stream_basic + 2;
  moqfetch_seq seq = {0};
  moqfetch_obj o;
  for (usz cut = 0; cut < 7; cut++) {
    usz off = 0;
    CHECK(
        moqfetch_obj_take(wired_span_of(b, cut), &off, &seq, &o) ==
        MOQCTL_INSUFFICIENT);
    CHECK(off == 0 && !seq.have_loc);
  }
}

static void test_moqfetch_obj_put_reject(void) {
  moqfetch_seq seq = {0};
  moqfetch_obj o   = {0};
  u8           out[4];
  usz          n = 0;
  o.flags        = 0x80;
  CHECK(!moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &seq, &o));
  o.flags   = 0x0c;
  o.payload = wired_span_of(out, 4);
  CHECK(!moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &seq, &o));
}

/* ===== more FETCH message cases (10.12) ===== */

/* Decodes a framed FETCH, checks it re-encodes to the same body. */
static int moqfetch_t_frame(const u8* msg, usz n, moqfetch_fetch* m) {
  wired_span body = moqfetch_t_body(msg, n, MOQFETCH_T_FETCH);
  int        r    = moqfetch_fetch_take(body, m);
  if (r == MOQCTL_OK) CHECK(moqfetch_t_reencode(m, body));
  return r;
}

/* Relative Joining with GROUP_ORDER Descending, Absolute Joining with no
 * parameters (hand-derived from 10.12.2 / 10.2.8). */
static void test_moqfetch_joining_vectors(void) {
  static const u8 rel[] = {0x16, 0x00, 0x07, 0x02, 0x02,
                           0x00, 0x01, 0x01, 0x22, 0x02};
  static const u8 abs[] = {0x16, 0x00, 0x05, 0x04, 0x03, 0x00, 0x09, 0x00};
  moqfetch_fetch  m;
  CHECK(moqfetch_t_frame(rel, sizeof rel, &m) == MOQCTL_OK);
  CHECK(m.request_id == 2 && m.fetch_type == MOQFETCH_RELATIVE_JOINING);
  CHECK(m.joining_request_id == 0 && m.joining_start == 1);
  CHECK(m.params.n == 1 && m.params.items[0].type == MOQCTL_PARAM_GROUP_ORDER);
  CHECK(m.params.items[0].u8v == 2);
  CHECK(moqfetch_t_frame(abs, sizeof abs, &m) == MOQCTL_OK);
  CHECK(m.request_id == 4 && m.fetch_type == MOQFETCH_ABSOLUTE_JOINING);
  CHECK(m.joining_request_id == 0 && m.joining_start == 9);
}

/* Four parameter encodings in one list, Types by cumulative Delta
 * (10.2): AUTHORIZATION_TOKEN (length-prefixed), FILL_TIMEOUT (varint),
 * SUBSCRIBER_PRIORITY and GROUP_ORDER (uint8). */
static void test_moqfetch_params_mix(void) {
  static const u8 b[] = {0x00, 0x02, 0x00, 0x00, 0x04, 0x03, 0x02, 0x03,
                         0x00, 0x07, 0x64, 0x16, 0x80, 0x02, 0x01};
  moqfetch_fetch  m;
  if (moqfetch_fetch_take(wired_span_of(b, sizeof b), &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.params.n == 4);
  CHECK(m.params.items[0].type == MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  CHECK(m.params.items[1].type == MOQCTL_PARAM_FILL_TIMEOUT);
  CHECK(m.params.items[1].vi == 100);
  CHECK(m.params.items[2].u8v == 128);
  CHECK(m.params.items[3].type == MOQCTL_PARAM_GROUP_ORDER);
  CHECK(moqfetch_t_reencode(&m, wired_span_of(b, sizeof b)));
}

/* Standalone with an empty Track Name, and every varint at 2^64-1 (the
 * 9-byte MOQT varint). */
static void test_moqfetch_standalone_extremes(void) {
  static const u8 name_a[] = {'a'};
  moqfetch_fetch  m        = {0};
  moqfetch_fetch  d;
  u8              out[64];
  usz             n    = 0;
  m.request_id         = ~0ULL;
  m.fetch_type         = MOQFETCH_STANDALONE;
  m.track.ns.n         = 1;
  m.track.ns.fields[0] = wired_span_of(name_a, 1);
  m.start              = (moqctl_loc){~0ULL, ~0ULL};
  m.end                = (moqctl_loc){~0ULL, ~0ULL};
  CHECK(moqfetch_fetch_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(n == 9 + 1 + 3 + 1 + 4 * 9 + 1);
  CHECK(moqfetch_fetch_take(wired_span_of(out, n), &d) == MOQCTL_OK);
  CHECK(d.request_id == ~0ULL && d.track.name.n == 0);
  CHECK(d.start.group == ~0ULL && d.end.object == ~0ULL);
  CHECK(moqfetch_t_reencode(&d, wired_span_of(out, n)));
  m                    = (moqfetch_fetch){0};
  m.fetch_type         = MOQFETCH_RELATIVE_JOINING;
  m.joining_request_id = ~0ULL;
  m.joining_start      = ~0ULL;
  n                    = 0;
  CHECK(moqfetch_fetch_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(moqfetch_fetch_take(wired_span_of(out, n), &d) == MOQCTL_OK);
  CHECK(d.joining_request_id == ~0ULL && d.joining_start == ~0ULL);
}

/* 2.4.1: a Full Track Name of exactly 4,096 bytes (namespace 4,095 + name
 * 1) is accepted; namespace 4,096 + name 1 is not. */
static void moqfetch_t_ftn(usz ns_len, int want) {
  static u8      body[16 + MOQCTL_MAX_FTN_LEN + 1];
  wired_mspan    m = wired_mspan_of(body, sizeof body);
  usz            n = 0;
  moqfetch_fetch f;
  body[n++] = 0x00; /* Request ID */
  body[n++] = 0x01; /* Standalone */
  body[n++] = 0x01; /* one namespace field */
  CHECK(moqvi_put(m, &n, ns_len));
  for (usz i = 0; i < ns_len; i++) body[n++] = 'n';
  body[n++] = 0x01;
  body[n++] = 'b';
  for (usz i = 0; i < 5; i++) body[n++] = 0x00; /* Start, End, no params */
  CHECK(moqfetch_fetch_take(wired_span_of(body, n), &f) == want);
}

static void test_moqfetch_ftn_bound(void) {
  moqfetch_t_ftn(MOQCTL_MAX_FTN_LEN - 1, MOQCTL_OK);
  moqfetch_t_ftn(MOQCTL_MAX_FTN_LEN, MOQCTL_VIOLATION);
}

/* 10: the largest Message Length (65,535) round trips; the bulk is an
 * AUTHORIZATION_TOKEN USE_VALUE Value. */
static void test_moqfetch_max_length(void) {
  static u8       msg[3 + MOQCTL_MAX_MSG_LEN];
  static const u8 head[] = {0x16, 0xff, 0xff, 0x00, 0x01, 0x01, 0x01, 0x61,
                            0x01, 0x62, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03};
  wired_mspan     m      = wired_mspan_of(msg, sizeof msg);
  usz             n      = 0;
  moqfetch_fetch  f;
  for (; n < sizeof head; n++) msg[n] = head[n];
  CHECK(moqvi_put(m, &n, sizeof msg - n - 3));
  msg[n++] = 0x03; /* USE_VALUE */
  msg[n++] = 0x00; /* Token Type */
  for (; n < sizeof msg; n++) msg[n] = (u8)n;
  CHECK(moqfetch_t_frame(msg, sizeof msg, &f) == MOQCTL_OK);
  CHECK(f.params.n == 1);
  CHECK(f.params.items[0].token.value.n == MOQCTL_MAX_MSG_LEN - 18);
}

/* 10.12 Fetch Type 2^64-1; an extra byte after the body's fields; a
 * parameter not defined for FETCH (LOCATION_FILTER 0x21); a Type Delta
 * pushing the cumulative Type past 2^64-1 (10.2). */
static void test_moqfetch_more_rejects(void) {
  static const u8 tmax[] = {0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0x00, 0x00, 0x00};
  static const u8 over[] = {0x16, 0x00, 0x06, 0x04, 0x03,
                            0x00, 0x09, 0x00, 0x00};
  static const u8 lf[] = {0x00, 0x02, 0x00, 0x00, 0x01, 0x21, 0x02, 0x02, 0x00};
  static const u8 wrap[] = {0x00, 0x02, 0x00, 0x00, 0x02, 0x20,
                            0x01, 0xff, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff, 0x01};
  moqfetch_fetch  m;
  usz             off = 0;
  u64             type;
  wired_span      body;
  CHECK(
      moqfetch_fetch_take(wired_span_of(tmax, sizeof tmax), &m) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqctl_peek_type(wired_span_of(over, sizeof over), &off, &type, &body) ==
      MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(moqfetch_fetch_take(body, &m) == MOQCTL_VIOLATION);
  CHECK(
      moqfetch_fetch_take(wired_span_of(lf, sizeof lf), &m) ==
      MOQCTL_VIOLATION);
  CHECK(
      moqfetch_fetch_take(wired_span_of(wrap, sizeof wrap), &m) ==
      MOQCTL_VIOLATION);
}

/* ===== more fetch stream / Object cases (11.4.4) ===== */

/* A FETCH_HEADER followed by FIN carries no Objects; an End of Range may
 * lead the stream and the next Object then continues from it. */
static void test_moqfetch_stream_cases(void) {
  static const u8 only_hdr[] = {0x05, 0x00};
  static const u8 eor_lead[] = {0x05, 0x00, 0x80, 0x8c, 0x05,
                                0x02, 0x13, 0x07, 0x40, 0x00};
  static const u8 bad[]      = {0x05, 0x00, 0x80, 0x8c, 0x05,
                                0x02, 0x03, 0x07, 0x00};
  moqfetch_obj    o[2];
  moqfetch_seq    seq = {0};
  usz             off = 2;
  CHECK(moqfetch_t_stream(only_hdr, sizeof only_hdr, 0, o, 2) == 0);
  CHECK(moqfetch_t_stream(eor_lead, sizeof eor_lead, 0, o, 2) == 2);
  CHECK(o[0].flags == MOQFETCH_EOR_NONEXISTENT);
  CHECK(o[0].group == 5 && o[0].object == 2);
  CHECK(o[1].group == 5 && o[1].object == 3 && o[1].subgroup == 7);
  CHECK(o[1].priority == 0x40 && o[1].payload.n == 0);
  CHECK(
      moqfetch_obj_take(wired_span_of(bad, sizeof bad), &off, &seq, o) ==
      MOQCTL_OK);
  CHECK(
      moqfetch_obj_take(wired_span_of(bad, sizeof bad), &off, &seq, o) ==
      MOQCTL_VIOLATION);
}

static u8 moqfetch_t_pay[128];

/* Every encoder choice of 11.4.4.1 in one ascending stream: absolute first
 * Object, implied +1, Object ID Delta (incl. 0), Group ID Delta 0, Group
 * change without Object ID Delta, subgroup modes 0-3, Priority implied and
 * explicit, Properties present / empty / absent, Datagram, Payload Length
 * 0 / 127 / 128, and both End of Range markers. */
static const u8 moqfetch_t_props[] = {0x0e, 0x40};

#define MOQFETCH_T_OBJ(f, g, o, hs, sg, p, pn)            \
  {                                                       \
    f, g, o, hs, sg, p, 0, {0, 0}, { moqfetch_t_pay, pn } \
  }

static moqfetch_obj moqfetch_t_asc[] = {
    MOQFETCH_T_OBJ(0x1c, 10, 0, 1, 0, 5, 0),
    MOQFETCH_T_OBJ(0x01, 10, 1, 1, 0, 5, 127),
    MOQFETCH_T_OBJ(0x05, 10, 4, 1, 0, 5, 128),
    MOQFETCH_T_OBJ(0x05, 10, 4, 1, 0, 5, 1),
    MOQFETCH_T_OBJ(0x0e, 11, 0, 1, 1, 5, 1),
    MOQFETCH_T_OBJ(0x0b, 12, 1, 1, 9, 5, 1),
    MOQFETCH_T_OBJ(0x11, 12, 2, 1, 9, 200, 1),
    MOQFETCH_T_OBJ(0x21, 12, 3, 1, 9, 200, 1),
    MOQFETCH_T_OBJ(0x21, 12, 4, 1, 9, 200, 1),
    MOQFETCH_T_OBJ(0x40, 12, 5, 0, 0, 200, 1),
    MOQFETCH_T_OBJ(0x03, 12, 6, 1, 4, 200, 1),
    MOQFETCH_T_OBJ(0x8c, 13, 5, 0, 0, 0, 0),
    MOQFETCH_T_OBJ(0x01, 13, 6, 1, 4, 200, 1),
    MOQFETCH_T_OBJ(0x10c, 13, 9, 0, 0, 0, 0),
    MOQFETCH_T_OBJ(0x00, 13, 10, 1, 0, 200, 0),
};

/* Descending: Group = prior - (Delta + 1), down to Group 0. */
static moqfetch_obj moqfetch_t_desc[] = {
    MOQFETCH_T_OBJ(0x1c, 5, 0, 1, 0, 1, 0),
    MOQFETCH_T_OBJ(0x08, 4, 1, 1, 0, 1, 0),
    MOQFETCH_T_OBJ(0x0c, 0, 7, 1, 0, 1, 0),
};

static void moqfetch_t_same_obj(const moqfetch_obj* a, const moqfetch_obj* b) {
  CHECK(a->flags == b->flags);
  CHECK(a->group == b->group && a->object == b->object);
  CHECK(a->has_subgroup == b->has_subgroup && a->subgroup == b->subgroup);
  CHECK(a->priority == b->priority && a->has_props == b->has_props);
  moqfetch_t_same(a->props.p, a->props.n, b->props);
  moqfetch_t_same(a->payload.p, a->payload.n, b->payload);
}

static void moqfetch_t_roundtrip(moqfetch_obj* objs, usz k, int desc) {
  static u8    out[2048];
  moqfetch_seq enc = {0};
  moqfetch_seq dec = {0};
  usz          n   = 0;
  usz          off = 0;
  enc.descending   = desc;
  dec.descending   = desc;
  for (usz i = 0; i < k; i++)
    CHECK(
        moqfetch_obj_put(wired_mspan_of(out, sizeof out), &n, &enc, &objs[i]));
  for (usz i = 0; i < k; i++) {
    moqfetch_obj d;
    CHECK(
        moqfetch_obj_take(wired_span_of(out, n), &off, &dec, &d) == MOQCTL_OK);
    moqfetch_t_same_obj(&d, &objs[i]);
  }
  CHECK(off == n);
}

static void test_moqfetch_obj_roundtrip(void) {
  for (usz i = 0; i < sizeof moqfetch_t_pay; i++)
    moqfetch_t_pay[i] = (u8)(i * 7 + 1);
  moqfetch_t_asc[7].has_props = 1;
  moqfetch_t_asc[7].props     = wired_span_of(moqfetch_t_props, 2);
  moqfetch_t_asc[8].has_props = 1;
  moqfetch_t_asc[8].props     = wired_span_of(moqfetch_t_props, 0);
  moqfetch_t_roundtrip(
      moqfetch_t_asc, sizeof moqfetch_t_asc / sizeof moqfetch_t_asc[0], 0);
  moqfetch_t_roundtrip(
      moqfetch_t_desc, sizeof moqfetch_t_desc / sizeof moqfetch_t_desc[0], 1);
}

/* 11.4.4.1: with 0x40 the two LSBs are ignored -- any of the four values
 * decodes to the same Object. */
static void test_moqfetch_obj_datagram_lsbs(void) {
  static const u8 first[] = {0x1c, 0x02, 0x00, 0x09, 0x00};
  for (u8 lsb = 0; lsb < 4; lsb++) {
    u8           next[] = {(u8)(0x40 | lsb), 0x00};
    moqfetch_seq seq    = {0};
    moqfetch_obj o;
    CHECK(moqfetch_t_one(first, sizeof first, &seq, &o) == MOQCTL_OK);
    CHECK(moqfetch_t_one(next, sizeof next, &seq, &o) == MOQCTL_OK);
    CHECK(!o.has_subgroup && o.group == 2 && o.object == 1);
    CHECK(o.priority == 9);
  }
}

/* Reserved flag values; a prior Subgroup after a Datagram Object (which
 * has none); Descending below Group 0; Object ID Delta past 2^64-1. */
static void test_moqfetch_obj_more_rejects(void) {
  static const u8 f100[]  = {0x81, 0x00, 0x00, 0x00, 0x00};
  static const u8 f10d[]  = {0x81, 0x0d, 0x00, 0x00, 0x00};
  static const u8 first[] = {0x1c, 0x02, 0x00, 0x09, 0x00};
  static const u8 dgram[] = {0x40, 0x00};
  static const u8 sg1[]   = {0x01, 0x00};
  static const u8 sg2[]   = {0x02, 0x00};
  static const u8 down3[] = {0x08, 0x02, 0x00};
  static const u8 big[]   = {0x1c, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff,
                             0xff, 0xff, 0xff, 0xfe, 0x00, 0x00};
  static const u8 od2[]   = {0x04, 0x02, 0x00};
  moqfetch_seq    seq     = {0};
  moqfetch_obj    o;
  CHECK(moqfetch_t_one(f100, sizeof f100, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(f10d, sizeof f10d, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(first, sizeof first, &seq, &o) == MOQCTL_OK);
  CHECK(moqfetch_t_one(dgram, sizeof dgram, &seq, &o) == MOQCTL_OK);
  CHECK(moqfetch_t_one(sg1, sizeof sg1, &seq, &o) == MOQCTL_VIOLATION);
  CHECK(moqfetch_t_one(sg2, sizeof sg2, &seq, &o) == MOQCTL_VIOLATION);
  seq.descending = 1;
  CHECK(moqfetch_t_one(down3, sizeof down3, &seq, &o) == MOQCTL_VIOLATION);
  seq = (moqfetch_seq){0};
  CHECK(moqfetch_t_one(big, sizeof big, &seq, &o) == MOQCTL_OK);
  CHECK(o.object == ~0ULL - 1);
  CHECK(moqfetch_t_one(od2, sizeof od2, &seq, &o) == MOQCTL_VIOLATION);
}

/* ===== moqfetch_req (version-neutral FETCH, ledger 3-7) ===== */

static void moqfetch_t_req19_frame(
    const moqfetch_fetch* src, moqfetch_req* out) {
  static u8 buf[128]; /* out's spans view it after return */
  usz       n = 0;
  CHECK(moqfetch_fetch_encode(wired_mspan_of(buf, sizeof buf), &n, src));
  CHECK(moqfetch_req19_take(wired_span_of(buf, n), out) == MOQCTL_OK);
}

/* d19 Standalone: End Location Object != 0 means "end, plus 1" (exclusive);
 * {group=1,object=0} on the wire means "whole group 1" (inclusive). */
static void test_moqfetch_req19_standalone_roundtrip(void) {
  static const u8 nb[] = {'a'};
  moqfetch_fetch  src  = {0};
  moqfetch_req    m;
  u8              out[128];
  usz             n      = 0;
  src.fetch_type         = MOQFETCH_STANDALONE;
  src.track.ns.n         = 1;
  src.track.ns.fields[0] = wired_span_of(nb, 1);
  src.track.name         = wired_span_of(nb, 1);
  src.start              = moqctl_loc_of(2, 3);
  src.end                = moqctl_loc_of(5, 1); /* -> inclusive {5,0} */
  moqfetch_t_req19_frame(&src, &m);
  CHECK(!m.is_joining);
  CHECK(m.range.sk == MOQCTL_RSK_ABS);
  CHECK(m.range.start_group == 2 && m.range.start_object == 3);
  CHECK(m.range.ek == MOQCTL_REK_OBJ);
  CHECK(m.range.end_group == 5 && m.range.end_object == 0);
  CHECK(moqfetch_req19_encode(wired_mspan_of(out, sizeof out), &n, &m));
  {
    u8  back[128];
    usz bn = 0;
    CHECK(moqfetch_fetch_encode(wired_mspan_of(back, sizeof back), &bn, &src));
    CHECK(bn == n);
    for (usz i = 0; i < n; i++) CHECK(out[i] == back[i]);
  }

  /* End Location Object == 0 -> whole group, inclusive end of that group
   * (MOQCTL_REK_GROUP, no explicit end_object). */
  src.end = moqctl_loc_of(7, 0);
  moqfetch_t_req19_frame(&src, &m);
  CHECK(m.range.ek == MOQCTL_REK_GROUP);
  CHECK(m.range.end_group == 7);
}

static void moqfetch_t_req19_joining(
    u64 fetch_type, u64 jreq, u64 jstart, moqfetch_req* out) {
  moqfetch_fetch src     = {0};
  src.fetch_type         = fetch_type;
  src.joining_request_id = jreq;
  src.joining_start      = jstart;
  moqfetch_t_req19_frame(&src, out);
}

static void test_moqfetch_req19_relative_joining_roundtrip(void) {
  moqfetch_req m;
  u8           out[64];
  usz          n = 0;
  moqfetch_t_req19_joining(MOQFETCH_RELATIVE_JOINING, 3, 9, &m);
  CHECK(m.is_joining);
  CHECK(m.fetch_type == MOQFETCH_RELATIVE_JOINING);
  CHECK(m.joining_request_id == 3 && m.joining_start == 9);
  CHECK(moqfetch_req19_encode(wired_mspan_of(out, sizeof out), &n, &m));
  {
    moqfetch_req back;
    CHECK(moqfetch_req19_take(wired_span_of(out, n), &back) == MOQCTL_OK);
    CHECK(back.is_joining && back.joining_request_id == 3);
    CHECK(back.joining_start == 9);
  }
}

static void test_moqfetch_req19_absolute_joining_roundtrip(void) {
  moqfetch_req m;
  u8           out[64];
  usz          n = 0;
  moqfetch_t_req19_joining(MOQFETCH_ABSOLUTE_JOINING, 1, 42, &m);
  CHECK(m.is_joining);
  CHECK(m.fetch_type == MOQFETCH_ABSOLUTE_JOINING);
  CHECK(m.joining_request_id == 1 && m.joining_start == 42);
  CHECK(moqfetch_req19_encode(wired_mspan_of(out, sizeof out), &n, &m));
  {
    moqfetch_req back;
    CHECK(moqfetch_req19_take(wired_span_of(out, n), &back) == MOQCTL_OK);
    CHECK(back.fetch_type == MOQFETCH_ABSOLUTE_JOINING);
    CHECK(back.joining_start == 42);
  }
}

/* Builds a draft-22 FETCH body by hand: Request ID, NS (1 field "a"),
 * Name ("b"), then either 0 Parameters or 1 (LOCATION_FILTER). */
static usz moqfetch_t_req22_build(u8* b, int with_filter) {
  usz n  = 0;
  b[n++] = 0x00; /* Request ID */
  b[n++] = 0x01; /* NS: 1 field */
  b[n++] = 0x01;
  b[n++] = 'a';
  b[n++] = 0x01; /* Name len 1 */
  b[n++] = 'b';
  if (!with_filter) {
    b[n++] = 0x00; /* Number of Parameters */
    return n;
  }
  b[n++] = 0x01; /* Number of Parameters */
  b[n++] = 0x21; /* Type Delta -> LOCATION_FILTER */
  b[n++] = 0x02; /* Location Filter Type 0x02 Absolute Start */
  b[n++] = 0x03; /* StartGroup */
  b[n++] = 0x04; /* StartObject */
  return n;
}

static void test_moqfetch_req22_with_filter_roundtrip(void) {
  u8           body[32];
  usz          n = moqfetch_t_req22_build(body, 1);
  moqfetch_req m;
  u8           out[32];
  usz          on = 0;
  CHECK(moqfetch_req22_take(wired_span_of(body, n), &m) == MOQCTL_OK);
  CHECK(!m.is_joining);
  CHECK(m.track.ns.n == 1 && m.track.ns.fields[0].p[0] == 'a');
  CHECK(m.track.name.n == 1 && m.track.name.p[0] == 'b');
  CHECK(m.range.sk == MOQCTL_RSK_ABS);
  CHECK(m.range.start_group == 3 && m.range.start_object == 4);
  CHECK(m.range.ek == MOQCTL_REK_UNBOUNDED);
  CHECK(moqfetch_req22_encode(wired_mspan_of(out, sizeof out), &on, &m));
  CHECK(on == n);
  for (usz i = 0; i < n; i++) CHECK(out[i] == body[i]);
}

/* SS9.20.9: "If omitted from FETCH ..., the fetch ... is unfiltered" ->
 * defaults to sk=ABS, start={0,0}, ek=UNBOUNDED (fetch everything), not a
 * rejection. The encoder always re-derives an explicit LOCATION_FILTER (it
 * cannot tell "omitted" from "explicit whole-track filter" apart once
 * decoded, and a receiver does not need to): round trip is semantic, not
 * byte-identical, for this absent-filter case. */
static void test_moqfetch_req22_no_filter_defaults(void) {
  u8           body[32];
  usz          n = moqfetch_t_req22_build(body, 0);
  moqfetch_req m, back;
  u8           out[32];
  usz          on = 0;
  CHECK(moqfetch_req22_take(wired_span_of(body, n), &m) == MOQCTL_OK);
  CHECK(m.range.sk == MOQCTL_RSK_ABS);
  CHECK(m.range.start_group == 0 && m.range.start_object == 0);
  CHECK(m.range.ek == MOQCTL_REK_UNBOUNDED);
  CHECK(moqfetch_req22_encode(wired_mspan_of(out, sizeof out), &on, &m));
  CHECK(moqfetch_req22_take(wired_span_of(out, on), &back) == MOQCTL_OK);
  CHECK(back.range.sk == m.range.sk && back.range.ek == m.range.ek);
  CHECK(back.range.start_group == m.range.start_group);
  CHECK(back.range.start_object == m.range.start_object);
  CHECK(back.track.ns.n == 1 && back.track.ns.fields[0].p[0] == 'a');
  CHECK(back.track.name.n == 1 && back.track.name.p[0] == 'b');
}

/* A malformed Track Namespace (a zero-length field, SS2.4.1) inside a
 * draft-22 FETCH body must reject with VIOLATION, not be silently
 * swallowed. */
static void test_moqfetch_req22_bad_ns_rejects(void) {
  static const u8 bad_ns[] = {0x00, 0x01, 0x00};
  moqfetch_req    m;
  CHECK(
      moqfetch_req22_take(wired_span_of(bad_ns, sizeof bad_ns), &m) ==
      MOQCTL_VIOLATION);
}

/* X1 (cross_version): the same NS/Name + absolute {2,3}..{5,0} inclusive
 * range decodes to the same moqctl_rangeloc shape from d19 Standalone and
 * d22 Absolute-Start-Group-End. */
static void test_moqfetch_req_cross_version_range(void) {
  static const u8 nb[]  = {'a'};
  moqfetch_fetch  src19 = {0};
  moqfetch_req    m19, m22;
  u8              body22[32];
  usz             n22      = 0;
  src19.fetch_type         = MOQFETCH_STANDALONE;
  src19.track.ns.n         = 1;
  src19.track.ns.fields[0] = wired_span_of(nb, 1);
  src19.track.name         = wired_span_of(nb, 1);
  src19.start              = moqctl_loc_of(2, 3);
  src19.end                = moqctl_loc_of(5, 0); /* whole group 5 */
  moqfetch_t_req19_frame(&src19, &m19);
  CHECK(m19.range.ek == MOQCTL_REK_GROUP);
  CHECK(m19.range.end_group == 5);

  body22[n22++] = 0x00;
  body22[n22++] = 0x01;
  body22[n22++] = 0x01;
  body22[n22++] = 'a';
  body22[n22++] = 0x01;
  body22[n22++] = 'b';
  body22[n22++] = 0x01; /* 1 parameter */
  body22[n22++] = 0x21; /* LOCATION_FILTER */
  body22[n22++] = 0x03; /* type 0x03: Absolute Start, Group End */
  body22[n22++] = 0x02; /* StartGroup */
  body22[n22++] = 0x03; /* StartObject */
  body22[n22++] = 0x03; /* EndGroupDelta = 3 -> end_group 2+3=5 */
  CHECK(moqfetch_req22_take(wired_span_of(body22, n22), &m22) == MOQCTL_OK);

  CHECK(m19.range.sk == m22.range.sk);
  CHECK(m19.range.start_group == m22.range.start_group);
  CHECK(m19.range.start_object == m22.range.start_object);
  CHECK(m19.range.ek == m22.range.ek);
  CHECK(m19.range.end_group == m22.range.end_group);
}

void test_moqfetch(void) {
  test_moqfetch_standalone_golden();
  test_moqfetch_joining_golden();
  test_moqfetch_bad_type_and_scope();
  test_moqfetch_length_mismatch();
  test_moqfetch_varint_boundaries();
  test_moqfetch_ok_golden();
  test_moqfetch_ok_reject();
  test_moqfetch_hdr();
  test_moqfetch_stream_golden();
  test_moqfetch_stream_end_of_range();
  test_moqfetch_obj_flags_reject();
  test_moqfetch_obj_after_eor_reject();
  test_moqfetch_obj_subgroup_modes();
  test_moqfetch_obj_group_order();
  test_moqfetch_obj_overflow();
  test_moqfetch_obj_truncated();
  test_moqfetch_obj_put_reject();
  test_moqfetch_eor_timed_out();
  test_moqfetch_joining_vectors();
  test_moqfetch_params_mix();
  test_moqfetch_standalone_extremes();
  test_moqfetch_ftn_bound();
  test_moqfetch_max_length();
  test_moqfetch_more_rejects();
  test_moqfetch_stream_cases();
  test_moqfetch_obj_roundtrip();
  test_moqfetch_obj_datagram_lsbs();
  test_moqfetch_obj_more_rejects();
  test_moqfetch_req19_standalone_roundtrip();
  test_moqfetch_req19_relative_joining_roundtrip();
  test_moqfetch_req19_absolute_joining_roundtrip();
  test_moqfetch_req22_with_filter_roundtrip();
  test_moqfetch_req22_no_filter_defaults();
  test_moqfetch_req22_bad_ns_rejects();
  test_moqfetch_req_cross_version_range();
}
