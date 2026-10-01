#include "test.h"

/* RFC 9114 4.1: HEADERS(:status field section) followed by DATA(body), and the
 * round trip back through the response parser recovers :status 200 and body. */
static void test_resp_build_roundtrip(void) {
  u8         b[] = {'h', 'i'};
  u8         out[32];
  wired_obuf ob        = {out, sizeof out, 0};
  h3req_resp resp      = {0};
  u64        idx       = 0;
  int        is_static = 0;
  CHECK(h3resp_build(200, 0, wired_span_of(b, sizeof b), &ob) == 1);
  CHECK(h3req_resp_parse(wired_span_of(out, ob.len), &resp) == 1);
  /* field section: 2-byte prefix then Indexed Field Line for :status 200. */
  CHECK(
      resp.headers.n == 3 && resp.headers.p[0] == 0x00 &&
      resp.headers.p[1] == 0x00);
  CHECK(
      qpack_indexed_decode(
          wired_span_of(resp.headers.p + 2, resp.headers.n - 2), &idx,
          &is_static) != 0);
  CHECK(is_static == 1 && idx == 25);
  CHECK(resp.body.n == 2 && resp.body.p[0] == 'h' && resp.body.p[1] == 'i');
}

/* An empty body emits the HEADERS frame only. */
static void test_resp_build_no_body(void) {
  u8         out[32];
  wired_obuf ob   = {out, sizeof out, 0};
  h3req_resp resp = {0};
  CHECK(h3resp_build(200, 0, wired_span_of(0, 0), &ob) == 1);
  CHECK(h3req_resp_parse(wired_span_of(out, ob.len), &resp) == 1);
  CHECK(resp.headers.n == 3 && resp.body.p == 0 && resp.body.n == 0);
}

/* Insufficient capacity fails without writing past the buffer. */
static void test_resp_build_overflow(void) {
  u8         b[] = {'h', 'i'};
  u8         out[4];
  wired_obuf ob = {out, sizeof out, 0};
  CHECK(h3resp_build(200, 0, wired_span_of(b, sizeof b), &ob) == 0);
}

/* content_type non-null adds a content-type field line after :status. */
static void test_resp_build_content_type(void) {
  u8         b[] = {'h', 'i'};
  u8         out[32];
  wired_obuf ob        = {out, sizeof out, 0};
  h3req_resp resp      = {0};
  u64        idx       = 0;
  int        is_static = 0;
  CHECK(
      h3resp_build(
          200, "text/html; charset=utf-8", wired_span_of(b, sizeof b), &ob) ==
      1);
  CHECK(h3req_resp_parse(wired_span_of(out, ob.len), &resp) == 1);
  CHECK(resp.headers.n == 4);
  CHECK(
      qpack_indexed_decode(
          wired_span_of(resp.headers.p + 2, 1), &idx, &is_static) != 0);
  CHECK(is_static == 1 && idx == 25); /* :status 200 */
  CHECK(
      qpack_indexed_decode(
          wired_span_of(resp.headers.p + 3, 1), &idx, &is_static) != 0);
  CHECK(is_static == 1 && idx == 52); /* content-type: text/html; ... */
}

/* The prefix (HEADERS + DATA header, no payload) followed by the body bytes
 * equals the full build byte for byte, so a body already in place needs no
 * copy; an empty body yields the HEADERS-only prefix. */
static void test_resp_build_prefix_matches_full(void) {
  u8         full[512], pre[64];
  u8         body[300];
  wired_obuf fb = {full, sizeof full, 0}, pb = {pre, sizeof pre, 0};
  for (usz i = 0; i < sizeof body; i++) body[i] = (u8)i;
  CHECK(h3resp_build(200, "text/html", wired_span_of(body, 300), &fb) == 1);
  CHECK(h3resp_prefix(200, "text/html", 300, &pb) == 1);
  CHECK(pb.len + 300 == fb.len);
  for (usz i = 0; i < pb.len; i++) CHECK(pre[i] == full[i]);
  for (usz i = 0; i < 300; i++) CHECK(full[pb.len + i] == body[i]);
  fb.len = 0;
  pb.len = 0;
  CHECK(h3resp_build(204, 0, wired_span_of(0, 0), &fb) == 1);
  CHECK(h3resp_prefix(204, 0, 0, &pb) == 1);
  CHECK(pb.len == fb.len);
}

/* Decode one Literal Field Line With Literal Name at *off and check it
 * carries (name, value). */
static int rb_litname_is(
    wired_span fs, usz* off, const char* name, const char* value) {
  u8             nb[32], vb[32];
  int            never = 0;
  qpack_fieldbuf fb    = {obuf_of(nb, sizeof nb), obuf_of(vb, sizeof vb)};
  usz            c     = qpack_literal_name_decode(
      wired_span_of(fs.p + *off, fs.n - *off), &never, &fb);
  *off += c;
  return c && fb.name.len == wired_cstr_len(name) &&
         fb.value.len == wired_cstr_len(value) &&
         ct_diffn(nb, (const u8*)name, fb.name.len) == 0 &&
         ct_diffn(vb, (const u8*)value, fb.value.len) == 0;
}

/* RFC 9204 4.5.6: a list of extra fields becomes one literal-name line
 * each, in order, after :status; an empty list adds none. */
static void test_resp_build_prefix_fields(void) {
  static const u8 n0[] = "location", v0[] = "/a", n1[] = "set-cookie",
                  v1[] = "x=1";
  qpack_field     f[2] = {
      {wired_span_of(n0, sizeof n0 - 1), wired_span_of(v0, sizeof v0 - 1)},
      {wired_span_of(n1, sizeof n1 - 1), wired_span_of(v1, sizeof v1 - 1)}};
  u8                     pre[128];
  wired_obuf             pb   = {pre, sizeof pre, 0};
  h3req_resp             resp = {0};
  qpackenc_status_result ins;
  usz off = 4; /* prefix (2) + :status 302, static index 66 (2) */
  CHECK(h3resp_prefix_fields_qenc(302, 0, 0, f, 2, 0, &ins, &pb) == 1);
  CHECK(h3req_resp_parse(wired_span_of(pre, pb.len), &resp) == 1);
  CHECK(rb_litname_is(resp.headers, &off, "location", "/a"));
  CHECK(rb_litname_is(resp.headers, &off, "set-cookie", "x=1"));
  CHECK(off == resp.headers.n);
  pb.len = 0;
  CHECK(h3resp_prefix_fields_qenc(302, 0, 0, f, 0, 0, &ins, &pb) == 1);
  CHECK(pb.len == 2 + 4); /* HEADERS type + length + 4-byte section */
}

void test_resp_build(void) {
  test_resp_build_prefix_fields();
  test_resp_build_prefix_matches_full();
  test_resp_build_roundtrip();
  test_resp_build_no_body();
  test_resp_build_overflow();
  test_resp_build_content_type();
}
