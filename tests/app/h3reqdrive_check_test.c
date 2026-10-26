#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "test.h"

/* RFC 9114 4.2 / 4.3 / 10.3, RFC 9110 5.5: request field-section validation
 * on receipt, driven through wired_h3reqdrive_recv_get -- the decoder the
 * server's request path (wired_h3srv_on_request) runs. */

static usz rc_cstr(const char* s) {
  usz i = 0;
  while (s[i]) {
    i++;
  }
  return i;
}

/* Append a Literal Field Line With Literal Name (RFC 9204 4.5.6). */
static void rc_lit(u8* fs, usz* off, const char* name, const char* value) {
  qpack_field f = {
      wired_span_of((const u8*)name, rc_cstr(name)),
      wired_span_of((const u8*)value, rc_cstr(value))};
  *off += qpack_literal_name_encode(wired_mspan_of(fs + *off, 128), 0, &f);
}

/* Section prefix plus :method GET (static 17) and :scheme https (23). */
static usz rc_head(u8* fs) {
  qpack_prefix pfx = {0, 0, 0};
  usz          off = qpack_prefix_encode(fs, 64, &pfx);
  off += qpack_indexed_encode(wired_mspan_of(fs + off, 64), 17, 1);
  off += qpack_indexed_encode(wired_mspan_of(fs + off, 64), 23, 1);
  return off;
}

/* A valid GET field section (:authority h, :path /) ahead of the caller's
 * own lines. */
static usz rc_get(u8* fs) {
  usz off = rc_head(fs);
  rc_lit(fs, &off, ":authority", "h");
  rc_lit(fs, &off, ":path", "/");
  return off;
}

/* Decode field section fs[0..n) as one request; 1 if it is accepted. */
static int rc_decode(const u8* fs, usz n, wired_h3reqdrive_req* r) {
  static u8     req[1024], scratch[1024];
  wired_obuf    ob     = {req, sizeof req, 0};
  h3conn_req_in req_in = {wired_span_of(fs, n), wired_span_of(0, 0)};
  if (!h3conn_send_request(0, &req_in, &ob)) {
    return 0;
  }
  return wired_h3reqdrive_recv_get(
      wired_span_of(req, ob.len), wired_mspan_of(scratch, sizeof scratch), r);
}

/* A valid GET plus one regular line (name, value); 1 if accepted. */
static int rc_with_line(const char* name, const char* value) {
  u8                   fs[512];
  usz                  off = rc_get(fs);
  wired_h3reqdrive_req r;
  rc_lit(fs, &off, name, value);
  return rc_decode(fs, off, &r);
}

/* RFC 9114 4.2 (9114-016): an uppercase field name is malformed. */
static void test_h3reqcheck_uppercase_name_rejected(void) {
  CHECK(rc_with_line("x-ok", "1"));
  CHECK(!rc_with_line("X-Bad", "1"));
  CHECK(!rc_with_line("expecT", "100-continue"));
}

/* RFC 9114 10.3 / RFC 9110 5.1 (9114-096): a name that is not a token is
 * malformed (SP, a separator, an empty name). */
static void test_h3reqcheck_non_token_name_rejected(void) {
  CHECK(rc_with_line("x-a.b_c~", "1"));
  CHECK(!rc_with_line("x a", "1"));
  CHECK(!rc_with_line("x(a)", "1"));
  CHECK(!rc_with_line("", "1"));
}

/* RFC 9114 10.3 / RFC 9110 5.5 (9114-096): a value octet outside
 * field-content (a control other than HTAB, or DEL) is malformed; HTAB,
 * SP and obs-text inside a value are fine. */
static void test_h3reqcheck_value_octets(void) {
  CHECK(rc_with_line("x-v", "a\tb c\x80\xff"));
  CHECK(!rc_with_line("x-v", "a\x01"));
  CHECK(!rc_with_line("x-v", "a\x7f"));
  CHECK(!rc_with_line("x-v", "a\x1f"));
}

/* RFC 9110 5.5 (9110-034): leading and trailing OWS is excluded before a
 * value is evaluated -- TE " trailers\t" is "trailers", and the kept
 * header reads back trimmed. */
static void test_h3reqcheck_value_ows_trimmed(void) {
  u8                   fs[512];
  usz                  off = rc_get(fs);
  wired_h3reqdrive_req r;
  wired_span           v = {0, 0};
  CHECK(rc_with_line("te", " trailers\t"));
  CHECK(!rc_with_line("te", " gzip "));
  rc_lit(fs, &off, "x-pad", " \t v w \t");
  CHECK(rc_decode(fs, off, &r));
  CHECK(wired_http_req_header(&r, wired_span_of((const u8*)"x-pad", 5), &v));
  CHECK(v.n == 3 && v.p[0] == 'v' && v.p[2] == 'w');
}

void test_h3reqcheck(void) {
  test_h3reqcheck_uppercase_name_rejected();
  test_h3reqcheck_non_token_name_rejected();
  test_h3reqcheck_value_octets();
  test_h3reqcheck_value_ows_trimmed();
}
