#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/request/h3reqenc/request_headers.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/prefix.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"

/* Compare a recovered (ptr,len) against a NUL-terminated literal. */
static int em_eq(const u8 *a, usz alen, const char *b) {
  usz i = 0;
  while (b[i]) {
    if (i >= alen || a[i] != (u8)b[i]) return 0;
    i++;
  }
  return i == alen;
}

/* RFC 9204 4.5.2: decode the first field line after the empty section prefix as
 * an Indexed Field Line and return its static-table index, or -1 if the leading
 * line is not a static Indexed Field Line. */
static i64 first_static_index(const u8 *fs, usz fs_len) {
  u64 index     = 0;
  int is_static = 0;
  usz off       = quic_qpack_prefix_decode(fs, fs_len, &(quic_qpack_prefix){0});
  usz c         = off ? quic_qpack_indexed_decode(
                    quic_span_of(fs + off, fs_len - off), &index, &is_static)
                      : 0;
  if (!c || !is_static) return -1;
  return (i64)index;
}

/* RFC 9204 Appendix A: each request method with a value-exact static entry
 * encodes its :method as a single Indexed Field Line at that static index. */
static void test_enc_method_static_index(void) {
  struct {
    const char *m;
    usz         mlen;
    i64         idx;
  } cases[] = {
      {"GET", 3, 17},     {"HEAD", 4, 18}, {"DELETE", 6, 16},
      {"OPTIONS", 7, 19}, {"POST", 4, 20}, {"PUT", 3, 21},
  };
  const u8              path[] = {'/'};
  const u8              auth[] = {'h'};
  quic_h3req_headers_in hin    = {
      quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)};
  for (usz i = 0; i < 6; i++) {
    u8        fs[256];
    quic_obuf ob = {fs, sizeof fs, 0};
    CHECK(quic_h3req_enc_method(
        quic_span_of((const u8 *)cases[i].m, cases[i].mlen), &hin, &ob));
    CHECK(first_static_index(fs, ob.len) == cases[i].idx);
  }
}

/* RFC 9204 4.5.4: a method absent from the static table (PATCH) is not a
 * leading Indexed Field Line; it goes out as a name-reference literal. */
static void test_enc_method_unknown_literal(void) {
  const u8              path[] = {'/'};
  const u8              auth[] = {'h'};
  u8                    fs[256];
  quic_obuf             ob  = {fs, sizeof fs, 0};
  quic_h3req_headers_in hin = {
      quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)};
  CHECK(quic_h3req_enc_method(quic_span_of((const u8 *)"PATCH", 5), &hin, &ob));
  CHECK(first_static_index(fs, ob.len) == -1);
}

/* Two byte ranges are identical. */
static int enc_bytes_eq(const u8 *a, usz alen, const u8 *b, usz blen) {
  if (alen != blen) return 0;
  for (usz i = 0; i < alen; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* RFC 9114 4.3.1: enc_get stays a thin wrapper -> identical bytes to
 * enc_method with :method = GET. */
static void test_enc_get_matches_method(void) {
  const u8              path[] = {'/', 'x'};
  const u8              auth[] = {'h', '1'};
  u8                    a[256], b[256];
  quic_obuf             aob = {a, sizeof a, 0}, bob = {b, sizeof b, 0};
  quic_h3req_headers_in hin = {
      quic_span_of(path, sizeof path), quic_span_of(auth, sizeof auth)};
  CHECK(quic_h3req_enc_get(&hin, &aob));
  CHECK(quic_h3req_enc_method(quic_span_of((const u8 *)"GET", 3), &hin, &bob));
  CHECK(enc_bytes_eq(a, aob.len, b, bob.len));
}

/* RFC 9114 4.1 / 4.3.1: a POST driven through send_method round-trips; recv_get
 * recovers all four pseudo-headers including the non-GET :method. */
static void test_send_method_post_roundtrip(void) {
  const u8                 path[] = {'/', 's'};
  const u8                 auth[] = {'e', 'x'};
  const u8                 body[] = {'h', 'i'};
  u8                       req[256], scratch[128];
  quic_obuf                req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req     r;
  wired_h3reqdrive_send_in in = {
      quic_span_of((const u8 *)"POST", 4), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(body, sizeof body)};
  CHECK(wired_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(em_eq(r.method, r.method_len, "POST"));
  CHECK(em_eq(r.scheme, r.scheme_len, "https"));
  CHECK(em_eq(r.authority, r.authority_len, "ex"));
  CHECK(em_eq(r.path, r.path_len, "/s"));
}

/* Scan the HTTP/3 frames in [h3,h3+n) for the first DATA frame, viewing its
 * payload in (*b,*blen). Returns 1 if found, 0 otherwise. */
static int scan_for_data(const u8 *h3, usz n, const u8 **b, usz *blen) {
  quic_h3_frame f   = {0};
  usz           off = 0;
  while (off < n) {
    usz used = quic_h3_frame_get(quic_span_of(h3 + off, n - off), &f);
    if (!used) return 0;
    off += used;
    if (f.type == QUIC_H3_FRAME_DATA) {
      *b    = f.payload;
      *blen = (usz)f.payload_len;
      return 1;
    }
  }
  return 0;
}

/* Locate the request stream's first DATA frame body; returns 1 with (*b,*blen)
 * viewing it, 0 if no DATA frame is present. */
static int find_data_body(const u8 *req, usz req_len, const u8 **b, usz *blen) {
  quic_stream_frame f;
  if (!quic_frame_get_stream(req, req_len, &f)) return 0;
  return scan_for_data(f.data, (usz)f.length, b, blen);
}

/* RFC 9114 4.1: send_method with a body appends a DATA frame; with no body the
 * stream carries only HEADERS (boundary: empty body). */
static void test_send_method_body_frame(void) {
  const u8                 path[] = {'/'};
  const u8                 auth[] = {'h'};
  const u8                 body[] = {'A', 'B', 'C'};
  u8                       req[256];
  quic_obuf                req_ob = {req, sizeof req, 0};
  usz                      blen   = 0;
  const u8                *b      = 0;
  wired_h3reqdrive_send_in in1    = {
      quic_span_of((const u8 *)"POST", 4), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(body, sizeof body)};
  CHECK(wired_h3reqdrive_send_method(0, &in1, &req_ob));
  CHECK(find_data_body(req, req_ob.len, &b, &blen));
  CHECK(blen == 3 && b[0] == 'A' && b[1] == 'B' && b[2] == 'C');
  /* boundary: no body -> no DATA frame */
  req_ob                       = (quic_obuf){req, sizeof req, 0};
  wired_h3reqdrive_send_in in2 = {
      quic_span_of((const u8 *)"GET", 3), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(0, 0)};
  CHECK(wired_h3reqdrive_send_method(0, &in2, &req_ob));
  CHECK(find_data_body(req, req_ob.len, &b, &blen) == 0);
}

/* RFC 9114 4.3.1: an asterisk-form :path (OPTIONS *) round-trips (boundary). */
static void test_send_method_asterisk_path(void) {
  const u8                 path[] = {'*'};
  const u8                 auth[] = {'e', 'x'};
  u8                       req[256], scratch[128];
  quic_obuf                req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req     r;
  wired_h3reqdrive_send_in in = {
      quic_span_of((const u8 *)"OPTIONS", 7), quic_span_of(path, sizeof path),
      quic_span_of(auth, sizeof auth), quic_span_of(0, 0)};
  CHECK(wired_h3reqdrive_send_method(0, &in, &req_ob));
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(em_eq(r.method, r.method_len, "OPTIONS"));
  CHECK(em_eq(r.path, r.path_len, "*"));
}

void test_h3reqenc(void) {
  test_enc_method_static_index();
  test_enc_method_unknown_literal();
  test_enc_get_matches_method();
  test_send_method_post_roundtrip();
  test_send_method_body_frame();
  test_send_method_asterisk_path();
}
