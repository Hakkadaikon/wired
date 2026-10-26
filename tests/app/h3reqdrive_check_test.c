#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "test.h"
#include "transport/stream/data/appdata/app_send.h"

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

/* Field section of (name, value) pairs, all literal-name lines; 1 if the
 * request decodes. */
static int rc_lines(const char* const* nv, usz pairs) {
  u8                   fs[512];
  qpack_prefix         pfx = {0, 0, 0};
  usz                  off = qpack_prefix_encode(fs, 64, &pfx);
  wired_h3reqdrive_req r;
  for (usz i = 0; i < pairs; i++) {
    rc_lit(fs, &off, nv[2 * i], nv[2 * i + 1]);
  }
  return rc_decode(fs, off, &r);
}

#define RC_LINES(...)                     \
  rc_lines(                               \
      (const char* const[]){__VA_ARGS__}, \
      sizeof((const char* const[]){__VA_ARGS__}) / sizeof(char*) / 2)

/* RFC 9114 4.3 / 4.3.1 (9114-022/023/025): exactly one each of :method,
 * :scheme and :path, every pseudo-header ahead of the regular fields, and
 * none unknown or response-only. */
static void test_h3reqcheck_pseudo_set(void) {
  CHECK(RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "/"));
  CHECK(!RC_LINES(":scheme", "https", ":authority", "h", ":path", "/"));
  CHECK(!RC_LINES(":method", "GET", ":authority", "h", ":path", "/"));
  CHECK(!RC_LINES(":method", "GET", ":scheme", "https", ":authority", "h"));
  CHECK(!RC_LINES(
      ":method", "GET", ":method", "GET", ":scheme", "https", ":authority", "h",
      ":path", "/"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "/",
      ":path", "/"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "/",
      ":foo", "x"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "/",
      ":status", "200"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", "x-a", "1", ":authority", "h",
      ":path", "/"));
}

/* RFC 9114 4.3.1 / RFC 9110 4.2 (9114-087, 9110-031): :authority carries
 * no userinfo and names a host; an https request has :authority or Host,
 * neither empty, the same value when both are present. */
static void test_h3reqcheck_authority(void) {
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "u@h", ":path", "/"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "", ":path", "/"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", ":443", ":path",
      "/"));
  CHECK(!RC_LINES(":method", "GET", ":scheme", "https", ":path", "/"));
  CHECK(RC_LINES(
      ":method", "GET", ":scheme", "https", ":path", "/", "host", "h"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":path", "/", "host", ""));
  CHECK(RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "/",
      "host", "h"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "/",
      "host", "g"));
  CHECK(RC_LINES(":method", "GET", ":scheme", "x-other", ":path", "/"));
}

/* RFC 9114 4.3.1 / RFC 9110 7.1 (9110-038): "*" is OPTIONS' alone. */
static void test_h3reqcheck_asterisk_only_options(void) {
  CHECK(RC_LINES(
      ":method", "OPTIONS", ":scheme", "https", ":authority", "h", ":path",
      "*"));
  CHECK(!RC_LINES(
      ":method", "GET", ":scheme", "https", ":authority", "h", ":path", "*"));
}

/* RFC 9114 4.4 / RFC 9110 9.3.6 (9114-029, 9110-022, 9110-043): a plain
 * CONNECT carries :authority host:port and neither :scheme nor :path. */
static void test_h3reqcheck_connect_shape(void) {
  CHECK(RC_LINES(":method", "CONNECT", ":authority", "h:443"));
  CHECK(!RC_LINES(":method", "CONNECT"));
  CHECK(!RC_LINES(
      ":method", "CONNECT", ":authority", "h:443", ":scheme", "https"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", "h:443", ":path", "/"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", "h"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", "h:"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", ":443"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", "h:0"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", "h:65536"));
  CHECK(!RC_LINES(":method", "CONNECT", ":authority", "h:4x3"));
  CHECK(RC_LINES(":method", "CONNECT", ":authority", "[::1]:65535"));
}

/* Append one HTTP/3 frame (type, payload) at h3[*n]. */
static void rc_frame(u8* h3, usz* n, u64 type, wired_span payload) {
  wired_obuf ob = {h3 + *n, 1024 - *n, 0};
  CHECK(h3_frame_put(&ob, type, payload));
  *n += ob.len;
}

/* Decode the request stream made of the frames in h3[0..n) (FIN set). */
static int rc_stream(const u8* h3, usz n, wired_h3reqdrive_req* r) {
  static u8 req[1200], scratch[1024];
  usz       req_len = 0;
  CHECK(appdata_frame_flat(0, 0, h3, n, 1, req, sizeof req, &req_len));
  return wired_h3reqdrive_recv_get(
      wired_span_of(req, req_len), wired_mspan_of(scratch, sizeof scratch), r);
}

/* A request stream of the given frame types (0x21: a reserved grease
 * type): the first HEADERS carries a valid GET, a later one an empty
 * trailer section, every other frame is empty. 1 if it decodes, with
 * *unexpected from the decode. */
static int rc_seq(const u64* types, usz count, int* unexpected) {
  static const u8      trailer[] = {0x00, 0x00};
  static u8            h3[1024];
  u8                   fs[128];
  usz                  fs_len = rc_get(fs), n = 0;
  wired_h3reqdrive_req r;
  int                  ok;
  for (usz i = 0; i < count; i++) {
    wired_span pl = wired_span_of(0, 0);
    if (types[i] == H3_FRAME_HEADERS) {
      pl = i ? wired_span_of(trailer, 2) : wired_span_of(fs, fs_len);
    }
    rc_frame(h3, &n, types[i], pl);
  }
  ok          = rc_stream(h3, n, &r);
  *unexpected = r.frame_unexpected;
  return ok;
}

#define RC_SEQ(u, ...)            \
  rc_seq(                         \
      (const u64[]){__VA_ARGS__}, \
      sizeof((const u64[]){__VA_ARGS__}) / sizeof(u64), (u))

/* RFC 9114 4.1 / 7.2.3-7.2.8 (9114-005/007/057/060/069): HEADERS, DATA*,
 * an optional trailer HEADERS, unknown types anywhere; nothing of the
 * message after the trailer, and no control-stream frame anywhere. Each
 * violation is flagged H3_FRAME_UNEXPECTED (a connection error). */
static void test_h3reqcheck_frame_sequence(void) {
  int u = 0;
  CHECK(RC_SEQ(&u, 1, 0, 0x21, 0, 1, 0x21) && !u);
  CHECK(!RC_SEQ(&u, 1, 0, 1, 0) && u);
  CHECK(!RC_SEQ(&u, 1, 1, 1) && u);
  CHECK(!RC_SEQ(&u, 0, 1) && u);
  for (u64 t = 3; t <= 0xd; t += (t == 4 ? 3 : t == 7 ? 6 : 1)) {
    CHECK(!RC_SEQ(&u, t, 1) && u); /* CANCEL_PUSH, SETTINGS, GOAWAY, */
    CHECK(!RC_SEQ(&u, 1, t) && u); /* MAX_PUSH_ID: before or after */
  }
}

void test_h3reqcheck(void) {
  test_h3reqcheck_uppercase_name_rejected();
  test_h3reqcheck_non_token_name_rejected();
  test_h3reqcheck_value_octets();
  test_h3reqcheck_value_ows_trimmed();
  test_h3reqcheck_pseudo_set();
  test_h3reqcheck_authority();
  test_h3reqcheck_asterisk_only_options();
  test_h3reqcheck_connect_shape();
  test_h3reqcheck_frame_sequence();
}
