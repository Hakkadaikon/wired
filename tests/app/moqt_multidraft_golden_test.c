#include "app/moqt/ctl/moqctl.h"
#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/ver/moqver.h"
#include "moqt_golden.h"
#include "test.h"

/* Golden vectors whose WIRE BYTES differ by draft (moqt_golden.json's
 * "versions" key): GOAWAY's trailing draft-18 Request ID, LOCATION_FILTER's
 * length-prefixed-vs-typed encoding, and FETCH's whole body shape. Each
 * check below loops MOQVER_D18/D19/D22 in one function (7-3): the golden
 * bytes differ per draft, but the version-neutral model they decode to
 * does not. */

static wired_span mqmd_body(const u8* g, usz n, int accept_unimpl) {
  usz        off  = 0;
  u64        type = 0;
  wired_span body = {0, 0};
  int        r    = moqctl_peek_type(wired_span_of(g, n), &off, &type, &body);
  CHECK(r == MOQCTL_OK || (accept_unimpl && r == MOQCTL_KNOWN_UNIMPLEMENTED));
  return body;
}

typedef struct {
  wired_span body;
  u64        want_request_id;
  int (*take)(wired_span, usz*, moqctl_goaway*);
  int (*put)(wired_mspan, usz*, const moqctl_goaway*);
} mqmd_goaway_case;

static mqmd_goaway_case mqmd_goaway_case_d18(void) {
  mqmd_goaway_case c;
  c.body = mqmd_body(
      g_moqt_ctl_goaway_empty_d18, G_MOQT_CTL_GOAWAY_EMPTY_D18_LEN, 0);
  c.want_request_id = 4;
  c.take            = moqctl_goaway18_take;
  c.put             = moqctl_goaway18_encode;
  return c;
}

static mqmd_goaway_case mqmd_goaway_case_other(void) {
  mqmd_goaway_case c;
  c.body = mqmd_body(g_moqt_ctl_goaway_empty, G_MOQT_CTL_GOAWAY_EMPTY_LEN, 0);
  c.want_request_id = 0;
  c.take            = moqctl_goaway_take;
  c.put             = moqctl_goaway_encode;
  return c;
}

static mqmd_goaway_case mqmd_goaway_case_for(int ver) {
  if (ver == MOQVER_D18) return mqmd_goaway_case_d18();
  return mqmd_goaway_case_other();
}

static void mqmd_goaway_same_bytes(
    const moqctl_goaway* m, const mqmd_goaway_case* c) {
  u8  out[16];
  usz n = 0;
  CHECK(c->put(wired_mspan_of(out, sizeof out), &n, m));
  CHECK(n == c->body.n);
  for (usz i = 0; i < n; i++) CHECK(out[i] == c->body.p[i]);
}

/* GOAWAY (0x10): draft-18 control-stream GOAWAY has a trailing [Request
 * ID]; draft-19/22 do not. moqctl_goaway18_take covers d18, moqctl_goaway_
 * take the other two -- both decode into the same moqctl_goaway model. */
static void mqmd_goaway_one(int ver) {
  mqmd_goaway_case c    = mqmd_goaway_case_for(ver);
  moqctl_goaway    m    = {0};
  usz              boff = 0;

  CHECK(c.take(c.body, &boff, &m) == MOQCTL_OK);
  CHECK(m.new_session_uri.n == 0);
  CHECK(m.timeout == 0);
  CHECK(m.request_id == c.want_request_id);
  mqmd_goaway_same_bytes(&m, &c);
}

static void test_moqt_golden_goaway_multidraft(void) {
  for (int ver = 0; ver < MOQVER_COUNT; ver++) mqmd_goaway_one(ver);
}

/* LOCATION_FILTER (0x21) inside SUBSCRIBE's parameters: draft-19 is
 * length-prefixed with Filter Type 0x04 (AbsoluteRange); draft-18 shares
 * the draft-19 wire form (18-vs-19 diff SS5); draft-22 drops the outer
 * Length and uses an explicit Filter Type 0x03. Both decode to the same
 * moqctl_rangeloc: Absolute start {5,0}, end = whole Group 5+3=8. */
static wired_span mqmd_subscribe_lf_body(int ver) {
  if (ver == MOQVER_D22)
    return mqmd_body(
        g_moqt_ctl_subscribe_params_d22, G_MOQT_CTL_SUBSCRIBE_PARAMS_D22_LEN,
        0);
  return mqmd_body(
      g_moqt_ctl_subscribe_params, G_MOQT_CTL_SUBSCRIBE_PARAMS_LEN, 0);
}

static void mqmd_subscribe_lf_one(int ver) {
  static moqctl_subscribe m;
  const moqctl_param*     p;
  wired_span              body = mqmd_subscribe_lf_body(ver);
  usz                     boff = 0;

  CHECK(moqctl_subscribe_take(ver, body, &boff, &m) == MOQCTL_OK);
  p = moqctl_params_find(&m.params, MOQCTL_PARAM_LOCATION_FILTER);
  CHECK(p != 0);
  CHECK(p->rl.sk == MOQCTL_RSK_ABS);
  CHECK(p->rl.start_group == 5);
  CHECK(p->rl.start_object == 0);
  CHECK(p->rl.ek == MOQCTL_REK_GROUP);
  CHECK(p->rl.end_group == 8);
}

static void test_moqt_golden_location_filter_multidraft(void) {
  for (int ver = 0; ver < MOQVER_COUNT; ver++) mqmd_subscribe_lf_one(ver);
}

/* FETCH (0x16): draft-18/19 share the Standalone/Joining body shape;
 * draft-22 drops Fetch Type and the Start/End Locations in favor of a
 * LOCATION_FILTER parameter. Both golden vectors are the same logical
 * range -- Absolute start {0,0}, End Location (End Group 1, whole group)
 * -- decoded through the version-neutral moqfetch_req. */
static wired_span mqmd_fetch_body(int ver) {
  if (ver == MOQVER_D22)
    return mqmd_body(
        g_moqt_ctl_fetch_standalone_d22, G_MOQT_CTL_FETCH_STANDALONE_D22_LEN,
        1);
  return mqmd_body(
      g_moqt_ctl_fetch_standalone, G_MOQT_CTL_FETCH_STANDALONE_LEN, 1);
}

static int mqmd_fetch_take(int ver, wired_span body, moqfetch_req* out) {
  if (ver == MOQVER_D22) return moqfetch_req22_take(body, out);
  return moqfetch_req19_take(ver, body, out);
}

static void mqmd_fetch_one(int ver) {
  moqfetch_req m    = {0};
  wired_span   body = mqmd_fetch_body(ver);

  CHECK(mqmd_fetch_take(ver, body, &m) == MOQCTL_OK);
  CHECK(!m.is_joining);
  CHECK(m.range.sk == MOQCTL_RSK_ABS);
  CHECK(m.range.start_group == 0);
  CHECK(m.range.start_object == 0);
  CHECK(m.range.ek == MOQCTL_REK_GROUP);
  CHECK(m.range.end_group == 1);
}

static void test_moqt_golden_fetch_multidraft(void) {
  for (int ver = 0; ver < MOQVER_COUNT; ver++) mqmd_fetch_one(ver);
}

/* Decodes a SUBSCRIBE golden body in draft ver and re-encodes it: the
 * server codec must reproduce the vector byte for byte (the vector is the
 * moqt_chat browser client's draft-22 wire, examples/moqt_chat). */
static void mqmd_subscribe_roundtrip(
    int ver, wired_span body, moqctl_subscribe* m) {
  u8  out[128];
  usz boff = 0, n = 0;
  CHECK(moqctl_subscribe_take(ver, body, &boff, m) == MOQCTL_OK);
  CHECK(boff == body.n);
  CHECK(moqctl_subscribe_encode(wired_mspan_of(out, sizeof out), &n, m));
  CHECK(n == body.n);
  for (usz i = 0; i < n && i < body.n; i++) CHECK(out[i] == body.p[i]);
}

/* LOCATION_FILTER Next Object: draft-19 Largest Object (length-prefixed
 * type 2) and draft-22 Next Object (0x05, no length) are the same start. */
static void test_moqt_golden_next_object_multidraft(void) {
  static moqctl_subscribe m19, m22;
  const moqctl_param*     p;
  mqmd_subscribe_roundtrip(
      MOQVER_D19,
      mqmd_body(
          g_moqt_ctl_subscribe_next_object,
          G_MOQT_CTL_SUBSCRIBE_NEXT_OBJECT_LEN, 0),
      &m19);
  mqmd_subscribe_roundtrip(
      MOQVER_D22,
      mqmd_body(
          g_moqt_ctl_subscribe_next_object_d22,
          G_MOQT_CTL_SUBSCRIBE_NEXT_OBJECT_D22_LEN, 0),
      &m22);
  p = moqctl_params_find(&m19.params, MOQCTL_PARAM_LOCATION_FILTER);
  CHECK(p != 0 && p->rl.sk == MOQCTL_RSK_NEXT_OBJ);
  p = moqctl_params_find(&m22.params, MOQCTL_PARAM_LOCATION_FILTER);
  CHECK(p != 0 && p->rl.sk == MOQCTL_RSK_NEXT_OBJ);
}

/* draft-22 SS9.20.15 FILL_PARAMETERS on SUBSCRIBE: the chat client's
 * history join, Next Object live plus a fill of Relative Start 65. */
static void test_moqt_golden_subscribe_fill_d22(void) {
  static moqctl_subscribe m;
  const moqctl_param*     p;
  moqfetch_fill           f = {0};
  mqmd_subscribe_roundtrip(
      MOQVER_D22,
      mqmd_body(
          g_moqt_ctl_subscribe_fill_d22, G_MOQT_CTL_SUBSCRIBE_FILL_D22_LEN, 0),
      &m);
  p = moqctl_params_find(&m.params, MOQCTL_PARAM_FILL_PARAMETERS);
  CHECK(p != 0);
  if (!p) return;
  CHECK(moqfetch_fill_take(p->bytes, &f) == MOQCTL_OK);
  CHECK(f.has_filter && !f.inherit);
  CHECK(f.range.sk == MOQCTL_RSK_REL_GROUP && f.range.start_group == 65);
}

/* A fetch stream with the draft-22-only End of Timed-Out Range (0x20C):
 * a draft-22 sequence takes every entry and ends on that marker at 4/2;
 * a draft-19 sequence rejects the same marker. */
static int mqmd_fetch_stream_last(int timed_out_ok, moqfetch_obj* last) {
  wired_span in = wired_span_of(
      g_moqt_data_fetch_stream_end_of_range_d22,
      sizeof g_moqt_data_fetch_stream_end_of_range_d22);
  usz          off  = 0;
  u64          rid  = 99;
  moqfetch_seq seq  = {0};
  int          r    = MOQCTL_OK;
  seq.eor_timed_out = timed_out_ok;
  CHECK(moqfetch_hdr_take(in, &off, &rid) == MOQCTL_OK);
  while (off < in.n && r == MOQCTL_OK)
    r = moqfetch_obj_take(in, &off, &seq, last);
  return r;
}

static void test_moqt_golden_fetch_timed_out_d22(void) {
  moqfetch_obj o;
  CHECK(mqmd_fetch_stream_last(1, &o) == MOQCTL_OK);
  CHECK(o.flags == MOQFETCH_EOR_TIMED_OUT && o.group == 4 && o.object == 2);
  CHECK(mqmd_fetch_stream_last(0, &o) == MOQCTL_VIOLATION);
}

void test_moqt_multidraft_golden(void) {
  test_moqt_golden_goaway_multidraft();
  test_moqt_golden_location_filter_multidraft();
  test_moqt_golden_fetch_multidraft();
  test_moqt_golden_next_object_multidraft();
  test_moqt_golden_subscribe_fill_d22();
  test_moqt_golden_fetch_timed_out_d22();
}
