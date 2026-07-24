#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/qpack/qpack/dynfind.h"
#include "app/qpack/qpack/dyntable.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpackdyn/field_decode.h"
#include "app/qpack/qpackdyn/field_encode.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "test.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/stream/data/appdata/app_recv.h"
#include "transport/stream/data/appdata/app_send.h"
#include "transport/stream/data/appdata/stream_send.h"

static int rd_eq(const u8* a, usz alen, const char* b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

/* RFC 9114 4.3.1: client encodes a GET, server decodes the field section and
 * recovers all four request pseudo-headers from one STREAM frame. */
static void test_reqdrive_stream(void) {
  const u8             path[] = {'/', 'i', 'n', 'd', 'e', 'x'};
  const u8             auth[] = {'e', 'x', '.', 'c', 'o', 'm'};
  u8                   req[256], scratch[128];
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;

  CHECK(wired_h3reqdrive_send_get(
      0,
      &(wired_h3reqdrive_get_in){
          quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)},
      &req_ob));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.method, r.method_len, "GET", 3));
  CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
  CHECK(rd_eq(r.authority, r.authority_len, "ex.com", 6));
  CHECK(rd_eq(r.path, r.path_len, "/index", 6));
  CHECK(r.body_len == 0); /* GET carries no DATA frame */
}

/* RFC 9114 4.1: a request = HEADERS [DATA...]. A POST with a body decodes its
 * :method and views the DATA-frame body. */
static void test_reqdrive_post_body(void) {
  static const u8          method[] = {'P', 'O', 'S', 'T'};
  const u8                 path[]   = {'/', 'u'};
  const u8                 auth[]   = {'h', '1'};
  const u8                 body[]   = {'h', 'e', 'l', 'l', 'o'};
  u8                       req[256], scratch[128];
  quic_obuf                req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req     r;
  wired_h3reqdrive_send_in in = {
      quic_span_of(method, sizeof method), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(body, sizeof body)};

  CHECK(wired_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.method, r.method_len, "POST", 4));
  CHECK(rd_eq(r.body, r.body_len, "hello", 5));
}

/* RFC 9114 4.1: an empty body (DATA frame of length 0) decodes to body_len 0
 * but is distinguished from a malformed remainder by succeeding. */
static void test_reqdrive_empty_body(void) {
  static const u8          method[] = {'P', 'U', 'T'};
  const u8                 path[]   = {'/', 'e'};
  const u8                 auth[]   = {'h', '1'};
  u8                       req[256], scratch[128];
  quic_obuf                req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req     r;
  wired_h3reqdrive_send_in in = {
      quic_span_of(method, sizeof method), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(0, 0)};

  CHECK(wired_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.method, r.method_len, "PUT", 3));
  CHECK(r.body_len == 0);
}

/* Length of a NUL-terminated literal (test-local). */
static usz cstr(const char* s) {
  usz i = 0;
  while (s[i]) i++;
  return i;
}

/* RFC 9204 4.5.6: a Literal Field Line With Literal Name carrying (name,value),
 * appended at *off in fs. */
static void put_litname(u8* fs, usz* off, const char* name, const char* value) {
  quic_qpack_field f = {
      quic_span_of((const u8*)name, cstr(name)),
      quic_span_of((const u8*)value, cstr(value))};
  *off += quic_qpack_literal_name_encode(quic_mspan_of(fs + *off, 64), 0, &f);
}

/* RFC 9114 4.3.1: an empty :path for an "http"/"https" request is malformed,
 * even though the same field-line forms decode a non-empty :path fine. */
static void test_reqdrive_empty_path_rejected(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, 64, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, 64), 17, 1); /* :method GET */
  put_litname(fs, &off, ":scheme", "https");
  put_litname(fs, &off, ":authority", "h");
  put_litname(fs, &off, ":path", ""); /* empty :path */
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(!wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
}

/* Regression: a normal non-empty :path still decodes fine (curl_field_section
 * already exercises this via every other test; this pins the boundary case
 * of the SHORTEST valid path, one octet, right next to the empty-path
 * rejection above). */
static void test_reqdrive_one_char_path_ok(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, 64, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, 64), 17, 1); /* :method GET */
  put_litname(fs, &off, ":scheme", "https");
  put_litname(fs, &off, ":authority", "h");
  put_litname(fs, &off, ":path", "/");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.path, r.path_len, "/", 1));
}

/* RFC 9114 4.3.1 / RFC 9204 4.5: build a curl/quiche-style request field
 * section: pseudo-headers in :method,:authority,:scheme,:path order using a
 * mix of indexed, name-reference and literal-name forms, plus a regular
 * user-agent header as a literal-name line. */
static usz curl_field_section(u8* fs) {
  quic_qpack_prefix  pfx  = {0, 0, 0};
  usz                off  = quic_qpack_prefix_encode(fs, 64, &pfx);
  quic_qpack_nameref path = {1, 1, 0};
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, 64), 17, 1); /* :method GET */
  put_litname(fs, &off, ":authority", "curl.test");
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, 64), 23, 1); /* :scheme https */
  off += quic_qpack_literal_namref_encode(
      quic_mspan_of(fs + off, 64), &path,
      quic_span_of((const u8*)"/get", 4)); /* :path */
  put_litname(fs, &off, "user-agent", "curl/8");
  return off;
}

/* RFC 9218 5: a `priority: u=1, i` request header lands on the decoded
 * request; without one the RFC defaults (u=3, i=0) apply. */
static void test_reqdrive_priority_header(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  {
    quic_qpack_prefix pfx = {0, 0, 0};
    off                   = quic_qpack_prefix_encode(fs, 64, &pfx);
    off += quic_qpack_indexed_encode(
        quic_mspan_of(fs + off, 64), 17, 1); /* :method GET */
    put_litname(fs, &off, "priority", "u=1, i");
  }
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(r.priority.urgency == 1 && r.priority.incremental == 1);
  /* a request without the header keeps the defaults */
  {
    u8                 fs2[64], req2[256];
    quic_obuf          ob2 = {req2, sizeof req2, 0};
    usz                n2  = curl_field_section(fs2);
    quic_h3conn_req_in in2 = {quic_span_of(fs2, n2), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &in2, &ob2));
    CHECK(wired_h3reqdrive_recv_get(
        quic_span_of(req2, ob2.len), quic_mspan_of(scratch, sizeof scratch),
        &r));
    CHECK(r.priority.urgency == 3 && r.priority.incremental == 0);
  }
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6: a regular `origin` header
 * lands on the decoded request; without one r.origin stays 0 (absent, not an
 * empty string). */
static void test_reqdrive_origin_header(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, 64, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, 64), 17, 1); /* :method GET */
  put_litname(fs, &off, "origin", "https://example.test");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.origin, r.origin_len, "https://example.test", 20));
  /* a request without the header leaves origin absent */
  {
    u8                 fs2[64], req2[256];
    quic_obuf          ob2 = {req2, sizeof req2, 0};
    usz                n2  = curl_field_section(fs2);
    quic_h3conn_req_in in2 = {quic_span_of(fs2, n2), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &in2, &ob2));
    CHECK(wired_h3reqdrive_recv_get(
        quic_span_of(req2, ob2.len), quic_mspan_of(scratch, sizeof scratch),
        &r));
    CHECK(r.origin == 0 && r.origin_len == 0);
  }
}

/* RFC 9204 4.5.6: a Literal Field Line With Literal Name whose VALUE runs
 * much longer than its (short) name -- e.g. a multi-entry subprotocol offer
 * list -- decodes intact even when the caller's scratch buffer is modest.
 * line_litname's scratch split must not hand the name half as much room as
 * the value: an even scr.n/2 split leaves too little for a value like this
 * one once the name's own (small) share is subtracted, exactly what a real
 * Extended CONNECT's wt-available-protocols header looks like on the wire. */
static void test_reqdrive_long_value_header(void) {
  static const char* const long_value =
      "sacred-riverboat first-lighthouse quiet-orchard second-avenue "
      "third-canyon fourth-meadow"; /* 88 octets */
  /* scratch=160: an even split gives the value half only 80 bytes (< the
   * 88-byte value, so an unfixed 50/50 split fails this); capping the name's
   * share at 64 leaves 96 for the value, which fits. */
  u8                   fs[192], req[384], scratch[160];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  quic_qpack_field     f   = {
      quic_span_of((const u8*)"origin", 6),
      quic_span_of((const u8*)long_value, cstr(long_value))};
  off = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  off += quic_qpack_literal_name_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 0, &f);
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.origin, r.origin_len, long_value, cstr(long_value)));
}

/* RFC 9114 10.3 / RFC 9110 5.5: a field NAME containing a forbidden octet
 * (CR here) makes the whole request malformed -- recv_get must reject the
 * request rather than hand the smuggled-newline name to the application. */
static void test_reqdrive_rejects_crlf_in_name(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  put_litname(fs, &off, "x-evil\r", "1");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(!wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
}

/* RFC 9114 10.3 / RFC 9110 5.5: a field VALUE containing a forbidden octet
 * (NUL here) makes the whole request malformed -- same rejection as the
 * name-side case above, exercised on the other half of the field line. The
 * NUL sits mid-buffer (not via a NUL-terminated C string) so it is actually
 * carried on the wire rather than truncating the value early. */
static void test_reqdrive_rejects_nul_in_value(void) {
  static const u8      evil_value[] = {'e', 'v', 'i', 'l', 0x00, 'x'};
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  quic_qpack_field     f   = {
      quic_span_of((const u8*)"origin", 6),
      quic_span_of(evil_value, sizeof evil_value)};
  off = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  off += quic_qpack_literal_name_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 0, &f);
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(!wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
}

/* RFC 9114 4.1: a message carrying a Transfer-Encoding field is malformed --
 * HTTP/2 and HTTP/3 have no meaning for it (only Content-Length is valid). */
static void test_reqdrive_rejects_transfer_encoding(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  put_litname(fs, &off, "transfer-encoding", "chunked");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(!wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
}

/* RFC 9114 4.2: a connection-specific field carried over from HTTP/1.1
 * (Connection here) makes the request malformed. */
static void test_reqdrive_rejects_connection_specific(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  put_litname(fs, &off, "connection", "keep-alive");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(!wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
}

/* RFC 9114 4.2: a TE field carrying a value other than "trailers" is
 * malformed; "trailers" itself is accepted. */
static void test_reqdrive_te_value(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  put_litname(fs, &off, "te", "gzip");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(!wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  {
    u8        fs2[96], req2[256];
    usz       off2 = quic_qpack_prefix_encode(fs2, sizeof fs2, &pfx);
    quic_obuf ob2  = {req2, sizeof req2, 0};
    off2 += quic_qpack_indexed_encode(
        quic_mspan_of(fs2 + off2, sizeof fs2 - off2), 17, 1); /* :method GET */
    put_litname(fs2, &off2, "te", "trailers");
    {
      quic_h3conn_req_in req_in = {quic_span_of(fs2, off2), quic_span_of(0, 0)};
      CHECK(quic_h3conn_send_request(0, &req_in, &ob2));
    }
    CHECK(wired_h3reqdrive_recv_get(
        quic_span_of(req2, ob2.len), quic_mspan_of(scratch, sizeof scratch),
        &r));
  }
}

/* RFC 9114 4.2.1: a single `cookie` field line lands on r.cookie verbatim. */
static void test_reqdrive_single_cookie(void) {
  u8                   fs[96], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  put_litname(fs, &off, "cookie", "a=1");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.cookie, r.cookie_len, "a=1", 3));
}

/* RFC 9114 4.2.1: multiple `cookie` field lines in a decompressed field
 * section are reassembled with the "; " delimiter into one value, as if the
 * peer had sent a single HTTP/1.1-style Cookie header. */
static void test_reqdrive_multi_cookie_joined(void) {
  u8                   fs[128], req[256], scratch[128];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, sizeof fs, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, sizeof fs - off), 17, 1); /* :method GET */
  put_litname(fs, &off, "cookie", "a=1");
  put_litname(fs, &off, "cookie", "b=2");
  put_litname(fs, &off, "cookie", "c=3");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.cookie, r.cookie_len, "a=1; b=2; c=3", 13));
}

/* RFC 9114 4.2.1: a request without any cookie field leaves r.cookie_len 0
 * (absent, not an empty joined string). */
static void test_reqdrive_no_cookie(void) {
  u8                   fs[64], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs);
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;

  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, fs_len), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(r.cookie_len == 0);
}

/* RFC 9114 4.1 / RFC 9204 4.5: a curl-style GET (reordered pseudo-headers,
 * mixed encodings, an extra regular header) decodes; all four pseudo-headers
 * are recovered by name regardless of order or count. */
static void test_reqdrive_curl_get(void) {
  u8                   fs[64], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs);
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;

  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, fs_len), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.method, r.method_len, "GET", 3));
  CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
  CHECK(rd_eq(r.authority, r.authority_len, "curl.test", 9));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 7.2.8: a real GREASE frame as sent by curl/quiche: a reserved type
 * 0x1f*N+0x21 (here matching the on-wire 8-byte varint type) carrying the
 * "GREASE is the word" payload. Returns bytes written. */
static usz put_grease_frame(u8* buf, usz cap) {
  const u8  g[] = {'G', 'R', 'E', 'A', 'S', 'E', ' ', 'i', 's',
                   ' ', 't', 'h', 'e', ' ', 'w', 'o', 'r', 'd'};
  quic_obuf ob  = {buf, cap, 0};
  return quic_h3_frame_put(
      &ob, 0x1f * 0x4000 + 0x21, quic_span_of(g, sizeof g));
}

/* RFC 9114 9 / 7.2.8: a request stream that begins with a GREASE frame before
 * the HEADERS frame (exactly what curl/quiche send) must skip the unknown
 * frame and still recover all four request pseudo-headers from the HEADERS. */
static void test_reqdrive_leading_grease(void) {
  u8                   fs[64], h3[256], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  wired_h3reqdrive_req r;
  quic_obuf            hob;

  h3_len = put_grease_frame(h3, sizeof(h3));
  hob    = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len +=
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.method, r.method_len, "GET", 3));
  CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
  CHECK(rd_eq(r.authority, r.authority_len, "curl.test", 9));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 9: two consecutive unknown frames before HEADERS are both skipped.
 */
static void test_reqdrive_two_greases(void) {
  u8                   fs[64], h3[256], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  wired_h3reqdrive_req r;
  quic_obuf            hob;

  h3_len = put_grease_frame(h3, sizeof(h3));
  h3_len += put_grease_frame(h3 + h3_len, sizeof(h3) - h3_len);
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len +=
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 9: a stream carrying only GREASE and no HEADERS must be rejected. */
static void test_reqdrive_grease_only(void) {
  u8                   h3[256], req[256], scratch[128];
  usz                  h3_len = put_grease_frame(h3, sizeof(h3)), req_len = 0;
  wired_h3reqdrive_req r;

  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(
      wired_h3reqdrive_recv_get(
          quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch),
          &r) == 0);
}

/* RFC 9114 9 / 4.1: a leading GREASE frame is skipped and the DATA frame after
 * HEADERS is still read as the body. */
static void test_reqdrive_grease_then_body(void) {
  u8                   fs[64], h3[256], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  const u8             body[] = {'b', 'o', 'd', 'y'};
  wired_h3reqdrive_req r;
  quic_obuf            hob;

  h3_len = put_grease_frame(h3, sizeof(h3));
  hob    = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len +=
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_DATA, quic_span_of(body, sizeof body));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
  CHECK(rd_eq(r.body, r.body_len, "body", 4));
}

/* RFC 9114 9 / 4.1: the DATA frame does not have to sit immediately after
 * HEADERS. An unknown/GREASE frame between HEADERS and DATA (curl interleaves
 * these) must be skipped and the DATA body still recovered. */
static void test_reqdrive_data_after_grease(void) {
  u8                   fs[64], h3[256], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  const u8             body[] = {'p', 'a', 'y'};
  wired_h3reqdrive_req r;
  quic_obuf            hob = {h3, sizeof h3, 0};

  h3_len =
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  h3_len += put_grease_frame(h3 + h3_len, sizeof(h3) - h3_len);
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_DATA, quic_span_of(body, sizeof body));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
  CHECK(rd_eq(r.body, r.body_len, "pay", 3));
}

/* RFC 9114 4.1: with two DATA frames present, the first one is viewed (the
 * later frame is not joined; documented limitation). */
static void test_reqdrive_multi_data(void) {
  u8                   fs[64], h3[256], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  const u8             a[] = {'a', 'a'}, b[] = {'b', 'b'};
  wired_h3reqdrive_req r;
  quic_obuf            hob = {h3, sizeof h3, 0};

  h3_len =
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len +=
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_DATA, quic_span_of(a, sizeof a));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len +=
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_DATA, quic_span_of(b, sizeof b));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.body, r.body_len, "aa", 2));
}

/* RFC 9001 5: derive a shared 1-RTT key pair for the end-to-end path. */
static void rd_keys(quic_initial_keys* k, quic_aes128* hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_derive(quic_span_of(dcid, 8), 1, QUIC_VERSION_1, k);
  quic_aes128_init(hp, k->hp);
}

/* RFC 9001 5 / RFC 9114 4.1: the GET request is sealed and opened through a
 * real 1-RTT packet before recv_get recovers :authority and :path. */
static void test_reqdrive_onertt(void) {
  quic_initial_keys    k;
  quic_aes128          hp;
  const u8             dcid[4] = {7, 7, 7, 7};
  const u8             path[]  = {'/', 'a'};
  const u8             auth[]  = {'h', '1'};
  u8                   req[256], pkt[256], reframed[256], scratch[128];
  quic_obuf            req_ob = {req, sizeof req, 0};
  usz                  total = 0, rf_len = 0;
  wired_h3reqdrive_req r;
  quic_stream_frame    f;
  u64                  sid = 0, off = 0;
  const u8*            sdata = 0;
  usz                  slen  = 0;
  int                  fin   = 0;
  rd_keys(&k, &hp);

  CHECK(wired_h3reqdrive_send_get(
      4,
      &(wired_h3reqdrive_get_in){
          quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)},
      &req_ob));
  CHECK(quic_frame_get_stream(req, req_ob.len, &f));
  CHECK(appdata_send_flat(
      &k, &hp, dcid, 4, 1, f.stream_id, f.data, (usz)f.length, f.fin, pkt,
      sizeof(pkt), &total));
  CHECK(appdata_recv_flat(
      &k, &hp, pkt, total, 4, &sid, &off, &sdata, &slen, &fin));
  CHECK(appdata_frame_flat(
      sid, off, sdata, slen, fin, reframed, sizeof(reframed), &rf_len));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(reframed, rf_len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.authority, r.authority_len, "h1", 2));
  CHECK(rd_eq(r.path, r.path_len, "/a", 2));
}

/* RFC 9114 4.1: a 200 response built by h3conn round-trips alongside the
 * driven request so the client recovers :status and body. */
static void test_reqdrive_response_status(void) {
  const u8         body[] = {'o', 'k'};
  u8               resp[256];
  quic_obuf        resp_ob  = {resp, sizeof resp, 0};
  quic_h3conn_resp resp_out = {0};

  {
    quic_h3conn_resp resp_in = {200, quic_span_of(body, sizeof body), 0};
    CHECK(quic_h3conn_send_response(0, &resp_in, &resp_ob));
  }
  CHECK(quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 200);
  CHECK(
      resp_out.body.n == 2 && resp_out.body.p[0] == 'o' &&
      resp_out.body.p[1] == 'k');
}

/* RFC 9204 4.5.2: a request value carried as a dynamic-table reference
 * round-trips: insert :authority into the dynamic table, encode the indexed
 * dynamic line, then decode it back to the same (name, value). */
/* Build a trailer field section (QPACK prefix + one literal-name field line
 * name/value) into fs, returning its length. */
static usz trailer_field_section(u8* fs, const char* name, const char* value) {
  quic_qpack_prefix pfx = {0, 0, 0};
  usz               off = quic_qpack_prefix_encode(fs, 64, &pfx);
  put_litname(fs, &off, name, value);
  return off;
}

/* Build a complete request STREAM frame: leading HEADERS (curl_field_section)
 * + one DATA frame ("hi") + a trailer HEADERS frame carrying one (name,value)
 * field line, into req. Returns the STREAM frame's total length. */
static usz build_request_with_trailer(
    u8* req, usz cap, const char* trailer_name, const char* trailer_value) {
  u8        fs[64], tfs[64], h3[256];
  usz       fs_len  = curl_field_section(fs);
  usz       tfs_len = trailer_field_section(tfs, trailer_name, trailer_value);
  usz       h3_len = 0, req_len = 0;
  const u8  body[] = {'h', 'i'};
  quic_obuf hob    = {h3, sizeof h3, 0};
  h3_len =
      quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_DATA, quic_span_of(body, sizeof body));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_HEADERS, quic_span_of(tfs, tfs_len));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, cap, &req_len));
  return req_len;
}

/* RFC 9114 4.3: a pseudo-header field in the trailer section is malformed,
 * even though the exact same name is valid in the leading field section. */
static void test_reqdrive_trailer_pseudoheader_rejected(void) {
  u8  req[256], scratch[128];
  usz req_len = build_request_with_trailer(req, sizeof req, ":status", "200");
  CHECK(!wired_h3reqdrive_trailer_ok(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch)));
}

/* A trailer section with only regular fields is accepted. */
static void test_reqdrive_trailer_regular_ok(void) {
  u8  req[256], scratch[128];
  usz req_len =
      build_request_with_trailer(req, sizeof req, "x-checksum", "abc123");
  CHECK(wired_h3reqdrive_trailer_ok(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch)));
}

/* A request with no trailer section at all is vacuously ok. */
static void test_reqdrive_no_trailer_ok(void) {
  u8                   fs[64], req[256], scratch[128];
  usz                  fs_len = curl_field_section(fs), req_len = 0;
  wired_h3reqdrive_req r;
  quic_obuf            req_ob = {req, sizeof req, 0};
  quic_h3conn_req_in   req_in = {quic_span_of(fs, fs_len), quic_span_of(0, 0)};
  CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  req_len = req_ob.len;
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(wired_h3reqdrive_trailer_ok(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch)));
}

static void test_reqdrive_dynamic_table(void) {
  quic_qpack_dyn   t;
  u8               fs[8];
  quic_obuf        ob       = quic_obuf_of(fs, sizeof(fs));
  usz              consumed = 0;
  u64              base, rel;
  quic_qpack_field f = {
      quic_span_of((const u8*)":authority", 10),
      quic_span_of((const u8*)"ex.com", 6)};
  quic_qpack_match m;
  quic_qpack_field d;
  quic_qpack_dyn_init(&t, 4096);

  CHECK(quic_qpack_dyn_insert(&t, &f));
  base = t.dropped + t.count;
  CHECK(quic_qpack_dyn_find(&t, &f, &m));
  rel = base - m.abs_index - 1;
  CHECK(quic_qdyn_indexed_dynamic(rel, &ob));
  quic_qdyn_src src = {&t, base, quic_span_of(fs, ob.len)};
  CHECK(quic_qdyn_decode_field(&src, &d, &consumed));
  CHECK(rd_eq(d.name.p, d.name.n, ":authority", 10));
  CHECK(rd_eq(d.value.p, d.value.n, "ex.com", 6));
}

void test_h3reqdrive(void) {
  test_reqdrive_priority_header();
  test_reqdrive_origin_header();
  test_reqdrive_long_value_header();
  test_reqdrive_stream();
  test_reqdrive_post_body();
  test_reqdrive_empty_body();
  test_reqdrive_grease_then_body();
  test_reqdrive_data_after_grease();
  test_reqdrive_multi_data();
  test_reqdrive_curl_get();
  test_reqdrive_leading_grease();
  test_reqdrive_two_greases();
  test_reqdrive_grease_only();
  test_reqdrive_onertt();
  test_reqdrive_empty_path_rejected();
  test_reqdrive_one_char_path_ok();
  test_reqdrive_trailer_pseudoheader_rejected();
  test_reqdrive_trailer_regular_ok();
  test_reqdrive_no_trailer_ok();
  test_reqdrive_response_status();
  test_reqdrive_dynamic_table();
  test_reqdrive_rejects_crlf_in_name();
  test_reqdrive_rejects_nul_in_value();
  test_reqdrive_rejects_transfer_encoding();
  test_reqdrive_rejects_connection_specific();
  test_reqdrive_te_value();
  test_reqdrive_single_cookie();
  test_reqdrive_multi_cookie_joined();
  test_reqdrive_no_cookie();
}
