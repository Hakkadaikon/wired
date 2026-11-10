#include "app/http3/core/h3conn/request.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3recv/req_frames.h"
#include "test.h"

/* RFC 9001 5: derive a shared 1-RTT key pair for the end-to-end path. */
static void rt_keys(initial_keys* k, aes128* hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  initial_derive(wired_span_of(dcid, 8), 1, VERSION_1, k);
  aes128_init(hp, k->hp);
}

/* RFC 9114 4.1: client request -> STREAM -> server reads HEADERS;
 * server response -> STREAM -> client recovers :status 200 and body. */
static void test_roundtrip_stream(void) {
  const u8   qhdrs[] = {0x00, 0x00, 0xd1}; /* prefix + indexed :path "/" */
  const u8   body[]  = {'h', 'i'};
  u8         req[256], resp[256];
  wired_obuf req_ob = {req, sizeof req, 0}, resp_ob = {resp, sizeof resp, 0};

  h3conn_req_in req_in = {
      wired_span_of(qhdrs, sizeof qhdrs), wired_span_of(0, 0)};
  h3conn_resp resp_in = {200, wired_span_of(body, sizeof body), 0};
  CHECK(h3conn_send_request(0, &req_in, &req_ob));

  /* server decodes the request STREAM frame and sees a HEADERS field section */
  {
    stream_frame f;
    wired_span   fs = {0, 0};
    CHECK(frame_get_stream(req, req_ob.len, &f));
    CHECK(f.stream_id == 0);
    CHECK(h3req_recv_first_headers(wired_span_of(f.data, (usz)f.length), &fs));
    CHECK(fs.n == sizeof(qhdrs));
  }

  CHECK(h3conn_send_response(0, &resp_in, &resp_ob));
  {
    h3conn_resp resp_out = {0};
    CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
    CHECK(resp_out.status == 200);
    CHECK(resp_out.body.n == sizeof(body));
    CHECK(resp_out.body.p[0] == 'h' && resp_out.body.p[1] == 'i');
  }
}

/* RFC 9001 5 / RFC 9114 4.1: same response, but sealed and opened through a
 * real 1-RTT packet (appdata) before recv_response decodes it. */
static void test_roundtrip_onertt(void) {
  initial_keys k;
  aes128       hp;
  const u8     dcid[4] = {9, 9, 9, 9};
  const u8     body[]  = {'o', 'k'};
  u8           h3[256], pkt[256];
  wired_obuf   h3_ob = {h3, sizeof h3, 0};
  usz          total = 0;
  rt_keys(&k, &hp);

  /* response STREAM frame */
  {
    h3conn_resp resp_in = {200, wired_span_of(body, sizeof body), 0};
    CHECK(h3conn_send_response(4, &resp_in, &h3_ob));
  }
  /* seal: re-wrap the HTTP/3 bytes as a sealed 1-RTT STREAM packet */
  {
    stream_frame f;
    CHECK(frame_get_stream(h3, h3_ob.len, &f));
    CHECK(appdata_send_flat(
        &k, &hp, dcid, 4, 1, f.stream_id, f.data, (usz)f.length, f.fin, pkt,
        sizeof(pkt), &total));
  }
  /* open the 1-RTT packet, then decode the response from its STREAM frame */
  {
    u64         sid = 0, off = 0;
    const u8*   sdata = 0;
    usz         slen  = 0;
    int         fin   = 0;
    u8          reframed[256];
    usz         rf_len   = 0;
    h3conn_resp resp_out = {0};
    CHECK(appdata_recv_flat(
        &k, &hp, pkt, total, 4, &sid, &off, &sdata, &slen, &fin));
    CHECK(appdata_frame_flat(
        sid, off, sdata, slen, fin, reframed, sizeof(reframed), &rf_len));
    CHECK(h3conn_recv_response(wired_span_of(reframed, rf_len), &resp_out));
    CHECK(resp_out.status == 200);
    CHECK(resp_out.body.n == sizeof(body));
    CHECK(resp_out.body.p[0] == 'o' && resp_out.body.p[1] == 'k');
  }
}

/* RFC 9114 4.1: empty body -> HEADERS only; recv_response reports no body. */
static void test_roundtrip_empty_body(void) {
  u8          resp[128];
  wired_obuf  resp_ob  = {resp, sizeof resp, 0};
  h3conn_resp resp_out = {0, wired_span_of((const u8*)1, 99), 0};

  {
    h3conn_resp resp_in = {404, wired_span_of(0, 0), 0};
    CHECK(h3conn_send_response(0, &resp_in, &resp_ob));
  }
  CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 404);
  CHECK(resp_out.body.n == 0);
}

/* cap too small: send paths report overflow. */
static void test_roundtrip_no_room(void) {
  const u8      qhdrs[] = {0x00, 0x00};
  u8            out[4];
  wired_obuf    ob     = {out, sizeof out, 0};
  h3conn_req_in req_in = {
      wired_span_of(qhdrs, sizeof qhdrs), wired_span_of(0, 0)};
  h3conn_resp resp_in = {200, wired_span_of(0, 0), 0};
  CHECK(!h3conn_send_request(0, &req_in, &ob));
  CHECK(!h3conn_send_response(0, &resp_in, &ob));
}

/* A body filling the whole 1500-byte HTTP/3 scratch cannot also carry the
 * HEADERS frame: the build fails even with ample STREAM room. */
static void test_roundtrip_body_too_big(void) {
  static const u8 big[1500] = {0};
  static u8       out[2048];
  wired_obuf      ob      = {out, sizeof out, 0};
  h3conn_resp     resp_in = {200, wired_span_of(big, sizeof big), 0};
  h3conn_req_in req_in = {wired_span_of(big, sizeof big), wired_span_of(0, 0)};
  CHECK(!h3conn_send_response(0, &resp_in, &ob));
  CHECK(!h3conn_send_request(0, &req_in, &ob));
}

/* RFC 9204 4.5.4: 201 is not in the static table, so it travels as a literal
 * with the :status name reference and decodes back through that path. */
static void test_roundtrip_literal_status(void) {
  u8          resp[128];
  wired_obuf  resp_ob  = {resp, sizeof resp, 0};
  h3conn_resp resp_in  = {201, wired_span_of(0, 0), 0};
  h3conn_resp resp_out = {0};
  CHECK(h3conn_send_response(0, &resp_in, &resp_ob));
  CHECK(h3conn_recv_response(wired_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 201);
}

/* Wrap h3 bytes in a FIN STREAM frame on stream 0 (RFC 9000 19.8, type
 * 0x0b = OFF 0, LEN 1, FIN 1). Returns the frame length. */
static usz rt_stream_wrap(const u8* h3, u8 n, u8* out) {
  out[0] = 0x0b;
  out[1] = 0x00;
  out[2] = n;
  bytes_memcpy(out + 3, h3, n);
  return (usz)n + 3;
}

static int rt_recv_h3(const u8* h3, u8 n) {
  u8          sf[64];
  h3conn_resp out = {0};
  usz         len = rt_stream_wrap(h3, n, sf);
  return h3conn_recv_response(wired_span_of(sf, len), &out);
}

/* Peer-malformed responses are rejected at each decode step. */
static void test_roundtrip_recv_malformed(void) {
  /* RFC 9204 4.5.4: literal :status (static name 24) with a 2-octet value */
  static const u8 short_val[] = {0x01, 0x07, 0x00, 0x00, 0x5f,
                                 0x09, 0x02, '2',  '0'};
  /* RFC 9204 4.5.2: indexed static index 99, past the 99-entry table */
  static const u8 bad_index[] = {0x01, 0x04, 0x00, 0x00, 0xff, 0x24};
  /* RFC 9204 4.5.1: HEADERS with no field-section prefix at all, and one
   * cut after the Required Insert Count -- whose lone byte 0xd9 would read
   * as the indexed field line :status 200 were the prefix skipped */
  static const u8 no_prefix[] = {0x01, 0x00};
  static const u8 cut_pfx[]   = {0x01, 0x01, 0xd9};
  /* RFC 9114 4.1: a response must open with HEADERS, not DATA */
  static const u8 data_first[] = {0x00, 0x01, 'x'};
  static const u8 ok_val[]     = {0x01, 0x08, 0x00, 0x00, 0x5f,
                                  0x09, 0x03, '2',  '0',  '1'};
  static const u8 type_only[]  = {0x0b}; /* STREAM type, no Stream ID */
  h3conn_resp     out          = {0};
  CHECK(rt_recv_h3(ok_val, sizeof ok_val));
  CHECK(!rt_recv_h3(short_val, sizeof short_val));
  CHECK(!rt_recv_h3(bad_index, sizeof bad_index));
  CHECK(!rt_recv_h3(no_prefix, sizeof no_prefix));
  CHECK(!rt_recv_h3(cut_pfx, sizeof cut_pfx));
  CHECK(!rt_recv_h3(data_first, sizeof data_first));
  CHECK(!h3conn_recv_response(wired_span_of(type_only, 1), &out));
}

void test_h3conn_roundtrip(void) {
  test_roundtrip_stream();
  test_roundtrip_onertt();
  test_roundtrip_empty_body();
  test_roundtrip_no_room();
  test_roundtrip_body_too_big();
  test_roundtrip_literal_status();
  test_roundtrip_recv_malformed();
}
