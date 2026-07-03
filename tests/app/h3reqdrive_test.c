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

static int rd_eq(const u8 *a, usz alen, const char *b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

/* RFC 9114 4.3.1: client encodes a GET, server decodes the field section and
 * recovers all four request pseudo-headers from one STREAM frame. */
static void test_reqdrive_stream(void) {
  const u8            path[] = {'/', 'i', 'n', 'd', 'e', 'x'};
  const u8            auth[] = {'e', 'x', '.', 'c', 'o', 'm'};
  u8                  req[256], scratch[128];
  quic_obuf           req_ob = {req, sizeof req, 0};
  quic_h3reqdrive_req r;

  CHECK(quic_h3reqdrive_send_get(
      0, &(quic_h3reqdrive_get_in){quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)}, &req_ob));
  CHECK(quic_h3reqdrive_recv_get(
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
  static const u8     method[] = {'P', 'O', 'S', 'T'};
  const u8            path[]   = {'/', 'u'};
  const u8            auth[]   = {'h', '1'};
  const u8            body[]   = {'h', 'e', 'l', 'l', 'o'};
  u8                  req[256], scratch[128];
  quic_obuf           req_ob = {req, sizeof req, 0};
  quic_h3reqdrive_req r;
  quic_h3reqdrive_send_in in = {
      quic_span_of(method, sizeof method), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(body, sizeof body)};

  CHECK(quic_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.method, r.method_len, "POST", 4));
  CHECK(rd_eq(r.body, r.body_len, "hello", 5));
}

/* RFC 9114 4.1: an empty body (DATA frame of length 0) decodes to body_len 0
 * but is distinguished from a malformed remainder by succeeding. */
static void test_reqdrive_empty_body(void) {
  static const u8     method[] = {'P', 'U', 'T'};
  const u8            path[]   = {'/', 'e'};
  const u8            auth[]   = {'h', '1'};
  u8                  req[256], scratch[128];
  quic_obuf           req_ob = {req, sizeof req, 0};
  quic_h3reqdrive_req r;
  quic_h3reqdrive_send_in in = {
      quic_span_of(method, sizeof method), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(0, 0)};

  CHECK(quic_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(rd_eq(r.method, r.method_len, "PUT", 3));
  CHECK(r.body_len == 0);
}

/* Length of a NUL-terminated literal (test-local). */
static usz cstr(const char *s) {
  usz i = 0;
  while (s[i]) i++;
  return i;
}

/* RFC 9204 4.5.6: a Literal Field Line With Literal Name carrying (name,value),
 * appended at *off in fs. */
static void put_litname(u8 *fs, usz *off, const char *name, const char *value) {
  quic_qpack_field f = {
      quic_span_of((const u8 *)name, cstr(name)),
      quic_span_of((const u8 *)value, cstr(value))};
  *off += quic_qpack_literal_name_encode(quic_mspan_of(fs + *off, 64), 0, &f);
}

/* RFC 9114 4.3.1 / RFC 9204 4.5: build a curl/quiche-style request field
 * section: pseudo-headers in :method,:authority,:scheme,:path order using a
 * mix of indexed, name-reference and literal-name forms, plus a regular
 * user-agent header as a literal-name line. */
static usz curl_field_section(u8 *fs) {
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
      quic_span_of((const u8 *)"/get", 4)); /* :path */
  put_litname(fs, &off, "user-agent", "curl/8");
  return off;
}

/* RFC 9114 4.1 / RFC 9204 4.5: a curl-style GET (reordered pseudo-headers,
 * mixed encodings, an extra regular header) decodes; all four pseudo-headers
 * are recovered by name regardless of order or count. */
static void test_reqdrive_curl_get(void) {
  u8                  fs[64], req[256], scratch[128];
  usz                 fs_len = curl_field_section(fs);
  quic_obuf           req_ob = {req, sizeof req, 0};
  quic_h3reqdrive_req r;

  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, fs_len), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(quic_h3reqdrive_recv_get(
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
static usz put_grease_frame(u8 *buf, usz cap) {
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
  u8                  fs[64], h3[256], req[256], scratch[128];
  usz                 fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  quic_h3reqdrive_req r;
  quic_obuf            hob;

  h3_len = put_grease_frame(h3, sizeof(h3));
  hob    = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.method, r.method_len, "GET", 3));
  CHECK(rd_eq(r.scheme, r.scheme_len, "https", 5));
  CHECK(rd_eq(r.authority, r.authority_len, "curl.test", 9));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 9: two consecutive unknown frames before HEADERS are both skipped.
 */
static void test_reqdrive_two_greases(void) {
  u8                  fs[64], h3[256], req[256], scratch[128];
  usz                 fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  quic_h3reqdrive_req r;
  quic_obuf            hob;

  h3_len = put_grease_frame(h3, sizeof(h3));
  h3_len += put_grease_frame(h3 + h3_len, sizeof(h3) - h3_len);
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
}

/* RFC 9114 9: a stream carrying only GREASE and no HEADERS must be rejected. */
static void test_reqdrive_grease_only(void) {
  u8                  h3[256], req[256], scratch[128];
  usz                 h3_len = put_grease_frame(h3, sizeof(h3)), req_len = 0;
  quic_h3reqdrive_req r;

  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(
      quic_h3reqdrive_recv_get(
          quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch),
          &r) == 0);
}

/* RFC 9114 9 / 4.1: a leading GREASE frame is skipped and the DATA frame after
 * HEADERS is still read as the body. */
static void test_reqdrive_grease_then_body(void) {
  u8                  fs[64], h3[256], req[256], scratch[128];
  usz                 fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  const u8             body[] = {'b', 'o', 'd', 'y'};
  quic_h3reqdrive_req r;
  quic_obuf            hob;

  h3_len = put_grease_frame(h3, sizeof(h3));
  hob    = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_DATA, quic_span_of(body, sizeof body));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
  CHECK(rd_eq(r.body, r.body_len, "body", 4));
}

/* RFC 9114 9 / 4.1: the DATA frame does not have to sit immediately after
 * HEADERS. An unknown/GREASE frame between HEADERS and DATA (curl interleaves
 * these) must be skipped and the DATA body still recovered. */
static void test_reqdrive_data_after_grease(void) {
  u8                  fs[64], h3[256], req[256], scratch[128];
  usz                 fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  const u8             body[] = {'p', 'a', 'y'};
  quic_h3reqdrive_req r;
  quic_obuf            hob = {h3, sizeof h3, 0};

  h3_len = quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  h3_len += put_grease_frame(h3 + h3_len, sizeof(h3) - h3_len);
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(
      &hob, QUIC_H3_FRAME_DATA, quic_span_of(body, sizeof body));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.path, r.path_len, "/get", 4));
  CHECK(rd_eq(r.body, r.body_len, "pay", 3));
}

/* RFC 9114 4.1: with two DATA frames present, the first one is viewed (the
 * later frame is not joined; documented limitation). */
static void test_reqdrive_multi_data(void) {
  u8                  fs[64], h3[256], req[256], scratch[128];
  usz                 fs_len = curl_field_section(fs), h3_len = 0, req_len = 0;
  const u8             a[] = {'a', 'a'}, b[] = {'b', 'b'};
  quic_h3reqdrive_req r;
  quic_obuf            hob = {h3, sizeof h3, 0};

  h3_len = quic_h3_frame_put(&hob, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fs_len));
  hob    = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(&hob, QUIC_H3_FRAME_DATA, quic_span_of(a, sizeof a));
  hob = (quic_obuf){h3 + h3_len, sizeof(h3) - h3_len, 0};
  h3_len += quic_h3_frame_put(&hob, QUIC_H3_FRAME_DATA, quic_span_of(b, sizeof b));
  CHECK(appdata_frame_flat(0, 0, h3, h3_len, 1, req, sizeof(req), &req_len));
  CHECK(quic_h3reqdrive_recv_get(
      quic_span_of(req, req_len), quic_mspan_of(scratch, sizeof scratch), &r));
  CHECK(rd_eq(r.body, r.body_len, "aa", 2));
}

/* RFC 9001 5: derive a shared 1-RTT key pair for the end-to-end path. */
static void rd_keys(quic_initial_keys *k, quic_aes128 *hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_derive(quic_span_of(dcid, 8), 1, k);
  quic_aes128_init(hp, k->hp);
}

/* RFC 9001 5 / RFC 9114 4.1: the GET request is sealed and opened through a
 * real 1-RTT packet before recv_get recovers :authority and :path. */
static void test_reqdrive_onertt(void) {
  quic_initial_keys   k;
  quic_aes128         hp;
  const u8            dcid[4] = {7, 7, 7, 7};
  const u8            path[]  = {'/', 'a'};
  const u8            auth[]  = {'h', '1'};
  u8                  req[256], pkt[256], reframed[256], scratch[128];
  quic_obuf           req_ob = {req, sizeof req, 0};
  usz                 total = 0, rf_len = 0;
  quic_h3reqdrive_req r;
  quic_stream_frame   f;
  u64                 sid = 0, off = 0;
  const u8           *sdata = 0;
  usz                 slen  = 0;
  int                 fin   = 0;
  rd_keys(&k, &hp);

  CHECK(quic_h3reqdrive_send_get(
      4, &(quic_h3reqdrive_get_in){quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)}, &req_ob));
  CHECK(quic_frame_get_stream(req, req_ob.len, &f));
  CHECK(appdata_send_flat(
      &k, &hp, dcid, 4, 1, f.stream_id, f.data, (usz)f.length, f.fin, pkt,
      sizeof(pkt), &total));
  CHECK(appdata_recv_flat(
      &k, &hp, pkt, total, 4, &sid, &off, &sdata, &slen, &fin));
  CHECK(appdata_frame_flat(
      sid, off, sdata, slen, fin, reframed, sizeof(reframed), &rf_len));
  CHECK(quic_h3reqdrive_recv_get(
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
    quic_h3conn_resp resp_in = {200, quic_span_of(body, sizeof body)};
    CHECK(quic_h3conn_send_response(0, &resp_in, &resp_ob));
  }
  CHECK(quic_h3conn_recv_response(
      quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 200);
  CHECK(resp_out.body.n == 2 && resp_out.body.p[0] == 'o' && resp_out.body.p[1] == 'k');
}

/* RFC 9204 4.5.2: a request value carried as a dynamic-table reference
 * round-trips: insert :authority into the dynamic table, encode the indexed
 * dynamic line, then decode it back to the same (name, value). */
static void test_reqdrive_dynamic_table(void) {
  quic_qpack_dyn   t;
  u8               fs[8];
  quic_obuf        ob       = quic_obuf_of(fs, sizeof(fs));
  usz              consumed = 0;
  u64              base, rel;
  quic_qpack_field f = {
      quic_span_of((const u8 *)":authority", 10),
      quic_span_of((const u8 *)"ex.com", 6)};
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
  test_reqdrive_response_status();
  test_reqdrive_dynamic_table();
}
