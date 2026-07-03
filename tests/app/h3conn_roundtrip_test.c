#include "app/http3/core/h3conn/request.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3recv/req_frames.h"
#include "test.h"

/* RFC 9001 5: derive a shared 1-RTT key pair for the end-to-end path. */
static void rt_keys(quic_initial_keys *k, quic_aes128 *hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_derive(quic_span_of(dcid, 8), 1, k);
  quic_aes128_init(hp, k->hp);
}

/* RFC 9114 4.1: client request -> STREAM -> server reads HEADERS;
 * server response -> STREAM -> client recovers :status 200 and body. */
static void test_roundtrip_stream(void) {
  const u8  qhdrs[] = {0x00, 0x00, 0xd1}; /* prefix + indexed :path "/" */
  const u8  body[]  = {'h', 'i'};
  u8        req[256], resp[256];
  quic_obuf req_ob = {req, sizeof req, 0}, resp_ob = {resp, sizeof resp, 0};

  quic_h3conn_req_in req_in = {
      quic_span_of(qhdrs, sizeof qhdrs), quic_span_of(0, 0)};
  quic_h3conn_resp resp_in = {200, quic_span_of(body, sizeof body)};
  CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));

  /* server decodes the request STREAM frame and sees a HEADERS field section */
  {
    quic_stream_frame f;
    quic_span         fs = {0, 0};
    CHECK(quic_frame_get_stream(req, req_ob.len, &f));
    CHECK(f.stream_id == 0);
    CHECK(quic_h3req_recv_first_headers(
        quic_span_of(f.data, (usz)f.length), &fs));
    CHECK(fs.n == sizeof(qhdrs));
  }

  CHECK(quic_h3conn_send_response(0, &resp_in, &resp_ob));
  {
    quic_h3conn_resp resp_out = {0};
    CHECK(
        quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
    CHECK(resp_out.status == 200);
    CHECK(resp_out.body.n == sizeof(body));
    CHECK(resp_out.body.p[0] == 'h' && resp_out.body.p[1] == 'i');
  }
}

/* RFC 9001 5 / RFC 9114 4.1: same response, but sealed and opened through a
 * real 1-RTT packet (appdata) before recv_response decodes it. */
static void test_roundtrip_onertt(void) {
  quic_initial_keys k;
  quic_aes128       hp;
  const u8          dcid[4] = {9, 9, 9, 9};
  const u8          body[]  = {'o', 'k'};
  u8                h3[256], pkt[256];
  quic_obuf         h3_ob = {h3, sizeof h3, 0};
  usz               total = 0;
  rt_keys(&k, &hp);

  /* response STREAM frame */
  {
    quic_h3conn_resp resp_in = {200, quic_span_of(body, sizeof body)};
    CHECK(quic_h3conn_send_response(4, &resp_in, &h3_ob));
  }
  /* seal: re-wrap the HTTP/3 bytes as a sealed 1-RTT STREAM packet */
  {
    quic_stream_frame f;
    CHECK(quic_frame_get_stream(h3, h3_ob.len, &f));
    CHECK(appdata_send_flat(
        &k, &hp, dcid, 4, 1, f.stream_id, f.data, (usz)f.length, f.fin, pkt,
        sizeof(pkt), &total));
  }
  /* open the 1-RTT packet, then decode the response from its STREAM frame */
  {
    u64              sid = 0, off = 0;
    const u8        *sdata = 0;
    usz              slen  = 0;
    int              fin   = 0;
    u8               reframed[256];
    usz              rf_len   = 0;
    quic_h3conn_resp resp_out = {0};
    CHECK(appdata_recv_flat(
        &k, &hp, pkt, total, 4, &sid, &off, &sdata, &slen, &fin));
    CHECK(appdata_frame_flat(
        sid, off, sdata, slen, fin, reframed, sizeof(reframed), &rf_len));
    CHECK(quic_h3conn_recv_response(quic_span_of(reframed, rf_len), &resp_out));
    CHECK(resp_out.status == 200);
    CHECK(resp_out.body.n == sizeof(body));
    CHECK(resp_out.body.p[0] == 'o' && resp_out.body.p[1] == 'k');
  }
}

/* RFC 9114 4.1: empty body -> HEADERS only; recv_response reports no body. */
static void test_roundtrip_empty_body(void) {
  u8               resp[128];
  quic_obuf        resp_ob  = {resp, sizeof resp, 0};
  quic_h3conn_resp resp_out = {0, quic_span_of((const u8 *)1, 99)};

  {
    quic_h3conn_resp resp_in = {404, quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_response(0, &resp_in, &resp_ob));
  }
  CHECK(quic_h3conn_recv_response(quic_span_of(resp, resp_ob.len), &resp_out));
  CHECK(resp_out.status == 404);
  CHECK(resp_out.body.n == 0);
}

/* cap too small: send paths report overflow. */
static void test_roundtrip_no_room(void) {
  const u8           qhdrs[] = {0x00, 0x00};
  u8                 out[4];
  quic_obuf          ob     = {out, sizeof out, 0};
  quic_h3conn_req_in req_in = {
      quic_span_of(qhdrs, sizeof qhdrs), quic_span_of(0, 0)};
  quic_h3conn_resp resp_in = {200, quic_span_of(0, 0)};
  CHECK(!quic_h3conn_send_request(0, &req_in, &ob));
  CHECK(!quic_h3conn_send_response(0, &resp_in, &ob));
}

void test_h3conn_roundtrip(void) {
  test_roundtrip_stream();
  test_roundtrip_onertt();
  test_roundtrip_empty_body();
  test_roundtrip_no_room();
}
