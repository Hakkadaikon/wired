#include "app/http3/core/h3conn/request.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3recv/req_frames.h"
#include "test.h"

/* RFC 9001 5: derive a shared 1-RTT key pair for the end-to-end path. */
static void rt_keys(quic_initial_keys *k, quic_aes128 *hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_derive(dcid, 8, 1, k);
  quic_aes128_init(hp, k->hp);
}

/* RFC 9114 4.1: client request -> STREAM -> server reads HEADERS;
 * server response -> STREAM -> client recovers :status 200 and body. */
static void test_roundtrip_stream(void) {
  const u8 qhdrs[] = {0x00, 0x00, 0xd1}; /* prefix + indexed :path "/" */
  const u8 body[]  = {'h', 'i'};
  u8       req[256], resp[256];
  usz      req_len = 0, resp_len = 0;

  CHECK(quic_h3conn_send_request(
      0, qhdrs, sizeof(qhdrs), 0, 0, req, sizeof(req), &req_len));

  /* server decodes the request STREAM frame and sees a HEADERS field section */
  {
    quic_stream_frame f;
    const u8         *fs     = 0;
    usz               fs_len = 0;
    CHECK(quic_frame_get_stream(req, req_len, &f));
    CHECK(f.stream_id == 0);
    CHECK(quic_h3req_recv_first_headers(f.data, (usz)f.length, &fs, &fs_len));
    CHECK(fs_len == sizeof(qhdrs));
  }

  CHECK(quic_h3conn_send_response(
      0, 200, body, sizeof(body), resp, sizeof(resp), &resp_len));
  {
    u16       status    = 0;
    const u8 *rbody     = 0;
    usz       rbody_len = 0;
    CHECK(
        quic_h3conn_recv_response(resp, resp_len, &status, &rbody, &rbody_len));
    CHECK(status == 200);
    CHECK(rbody_len == sizeof(body));
    CHECK(rbody[0] == 'h' && rbody[1] == 'i');
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
  usz               h3_len = 0, total = 0;
  rt_keys(&k, &hp);

  /* response STREAM frame */
  CHECK(quic_h3conn_send_response(
      4, 200, body, sizeof(body), h3, sizeof(h3), &h3_len));
  /* seal: re-wrap the HTTP/3 bytes as a sealed 1-RTT STREAM packet */
  {
    quic_stream_frame f;
    CHECK(quic_frame_get_stream(h3, h3_len, &f));
    CHECK(quic_appdata_send(
        &k, &hp, dcid, 4, 1, f.stream_id, f.data, (usz)f.length, f.fin, pkt,
        sizeof(pkt), &total));
  }
  /* open the 1-RTT packet, then decode the response from its STREAM frame */
  {
    u64       sid = 0, off = 0;
    const u8 *sdata = 0;
    usz       slen  = 0;
    int       fin   = 0;
    u8        reframed[256];
    usz       rf_len    = 0;
    u16       status    = 0;
    const u8 *rbody     = 0;
    usz       rbody_len = 0;
    CHECK(quic_appdata_recv(
        &k, &hp, pkt, total, 4, &sid, &off, &sdata, &slen, &fin));
    CHECK(quic_appdata_stream_frame(
        sid, off, sdata, slen, fin, reframed, sizeof(reframed), &rf_len));
    CHECK(quic_h3conn_recv_response(
        reframed, rf_len, &status, &rbody, &rbody_len));
    CHECK(status == 200);
    CHECK(rbody_len == sizeof(body));
    CHECK(rbody[0] == 'o' && rbody[1] == 'k');
  }
}

/* RFC 9114 4.1: empty body -> HEADERS only; recv_response reports no body. */
static void test_roundtrip_empty_body(void) {
  u8        resp[128];
  usz       resp_len  = 0;
  u16       status    = 0;
  const u8 *rbody     = (const u8 *)1;
  usz       rbody_len = 99;

  CHECK(quic_h3conn_send_response(0, 404, 0, 0, resp, sizeof(resp), &resp_len));
  CHECK(quic_h3conn_recv_response(resp, resp_len, &status, &rbody, &rbody_len));
  CHECK(status == 404);
  CHECK(rbody_len == 0);
}

/* cap too small: send paths report overflow. */
static void test_roundtrip_no_room(void) {
  const u8 qhdrs[] = {0x00, 0x00};
  u8       out[4];
  usz      n = 0;
  CHECK(!quic_h3conn_send_request(
      0, qhdrs, sizeof(qhdrs), 0, 0, out, sizeof(out), &n));
  CHECK(!quic_h3conn_send_response(0, 200, 0, 0, out, sizeof(out), &n));
}

void test_h3conn_roundtrip(void) {
  test_roundtrip_stream();
  test_roundtrip_onertt();
  test_roundtrip_empty_body();
  test_roundtrip_no_room();
}
