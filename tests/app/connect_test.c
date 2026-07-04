#include "test.h"

/* method=CONNECT with :authority and no :scheme/:path is valid. */
static void test_connect_ok(void) {
  quic_h3_connect_flags f = {1, 1, 0, 0};
  CHECK(quic_h3_connect_ok(&f) == 1);
}

/* Missing :method CONNECT or :authority is invalid. */
static void test_connect_required(void) {
  quic_h3_connect_flags f1 = {0, 1, 0, 0};
  quic_h3_connect_flags f2 = {1, 0, 0, 0};
  CHECK(quic_h3_connect_ok(&f1) == 0); /* not CONNECT */
  CHECK(quic_h3_connect_ok(&f2) == 0); /* no :authority */
}

/* Presence of :scheme or :path is forbidden. */
static void test_connect_forbidden(void) {
  quic_h3_connect_flags f1 = {1, 1, 1, 0};
  quic_h3_connect_flags f2 = {1, 1, 0, 1};
  quic_h3_connect_flags f3 = {1, 1, 1, 1};
  CHECK(quic_h3_connect_ok(&f1) == 0); /* has :scheme */
  CHECK(quic_h3_connect_ok(&f2) == 0); /* has :path */
  CHECK(quic_h3_connect_ok(&f3) == 0); /* both */
}

/* RFC 9114 4.4 / RFC 9204 4.5: enc_connect emits exactly two field lines after
 * the section prefix: :method=CONNECT (Indexed, static index 15) and :authority
 * (Literal With Name Reference, static name index 0). No :scheme/:path. Decode
 * with the public QPACK primitives and confirm the bytes end exactly there. */
static void test_connect_encode_two_fields(void) {
  static const u8 authority[] = {'h', 'o', 's', 't', ':', '4', '4', '3'};
  u8              out[64];
  quic_obuf       ob = {out, sizeof out, 0};
  CHECK(
      quic_h3req_enc_connect(quic_span_of(authority, sizeof authority), &ob) ==
      1);
  usz n = ob.len;

  quic_qpack_prefix pfx = {1, 1, 1};
  usz               off = quic_qpack_prefix_decode(out, n, &pfx);
  CHECK(off > 0);

  u64 idx       = 0;
  int is_static = 0;
  usz c         = quic_qpack_indexed_decode(
      quic_span_of(out + off, n - off), &idx, &is_static);
  CHECK(c > 0 && is_static == 1 && idx == 15); /* :method CONNECT */
  off += c;

  quic_qpack_nameref nr = {0, 0, 0};
  u8                 val[32];
  quic_obuf          vb = quic_obuf_of(val, sizeof val);
  c                     = quic_qpack_literal_namref_decode(
      quic_span_of(out + off, n - off), &nr, &vb);
  CHECK(c > 0 && nr.is_static == 1 && nr.index == 0); /* :authority name ref */
  CHECK(vb.len == sizeof authority && val[0] == 'h' && val[7] == '3');
  off += c;
  CHECK(off == n); /* no :scheme/:path follow */
}

/* A decoded request is rejected as a CONNECT unless it is exactly
 * method=CONNECT + authority with no scheme/path. */
static void test_connect_req_ok_rejects(void) {
  static const u8      m[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  static const u8      a[] = {'h'};
  static const u8      s[] = {'h', 't', 't', 'p', 's'};
  static const u8      p[] = {'/'};
  wired_h3reqdrive_req r   = {0};
  r.method                 = m;
  r.method_len             = 7;
  r.authority              = a;
  r.authority_len          = 1;
  CHECK(quic_h3_connect_req_ok(&r) == 1); /* valid CONNECT */

  r.scheme     = s;
  r.scheme_len = sizeof s;
  CHECK(quic_h3_connect_req_ok(&r) == 0); /* :scheme forbidden */
  r.scheme   = 0;
  r.path     = p;
  r.path_len = 1;
  CHECK(quic_h3_connect_req_ok(&r) == 0); /* :path forbidden */
  r.path          = 0;
  r.authority     = 0;
  r.authority_len = 0;
  CHECK(quic_h3_connect_req_ok(&r) == 0); /* no :authority */
  r.authority     = a;
  r.authority_len = 1;
  r.method_len    = 3;
  CHECK(quic_h3_connect_req_ok(&r) == 0); /* method != CONNECT */
}

/* RFC 9110 9.3.6: a 2xx response establishes the tunnel; >=3xx does not. */
static void test_connect_established(void) {
  CHECK(quic_h3_connect_established(200) == 1);
  CHECK(quic_h3_connect_established(201) == 1);
  CHECK(quic_h3_connect_established(299) == 1);
  CHECK(quic_h3_connect_established(199) == 0);
  CHECK(quic_h3_connect_established(300) == 0);
  CHECK(quic_h3_connect_established(404) == 0);
  CHECK(quic_h3_connect_established(502) == 0);
}

/* Forward-only lifecycle: req -> validated -> established(2xx) -> relay ->
 * closed. No relay before a 2xx, tunnel established once, no return after
 * close. */
static void test_connect_state_forward(void) {
  quic_h3_tunnel st;
  quic_h3_tunnel_init(&st);
  CHECK(st == QUIC_H3_TUNNEL_REQ);

  /* relay is refused before a 2xx response. */
  CHECK(quic_h3_tunnel_relay(&st) == 0);
  CHECK(st == QUIC_H3_TUNNEL_REQ);

  quic_h3_tunnel_validated(&st);
  CHECK(st == QUIC_H3_TUNNEL_VALIDATED);
  CHECK(quic_h3_tunnel_relay(&st) == 0); /* still no 2xx */

  /* >=3xx fails the tunnel; it never reaches established. */
  quic_h3_tunnel st2 = st;
  CHECK(quic_h3_tunnel_response(&st2, 502) == 0);
  CHECK(st2 == QUIC_H3_TUNNEL_FAILED);
  CHECK(quic_h3_tunnel_relay(&st2) == 0);

  /* 2xx establishes the tunnel exactly once. */
  CHECK(quic_h3_tunnel_response(&st, 200) == 1);
  CHECK(st == QUIC_H3_TUNNEL_ESTABLISHED);
  CHECK(quic_h3_tunnel_response(&st, 200) == 0); /* not established twice */
  CHECK(st == QUIC_H3_TUNNEL_ESTABLISHED);

  CHECK(quic_h3_tunnel_relay(&st) == 1); /* relay allowed now */
  CHECK(st == QUIC_H3_TUNNEL_RELAY);

  quic_h3_tunnel_close(&st);
  CHECK(st == QUIC_H3_TUNNEL_CLOSED);
  CHECK(quic_h3_tunnel_relay(&st) == 0); /* no relay after close */
  CHECK(st == QUIC_H3_TUNNEL_CLOSED);    /* no return to RELAY */
}

/* RFC 9220 3: build a request STREAM frame with a HEADERS field section
 * carrying :method=CONNECT, :authority and, when want_protocol, a literal
 * :protocol field, then a matching QUIC STREAM frame header. Mirrors the
 * wire shape wired_h3reqdrive_recv_get expects. */
static usz build_connect_stream(
    int want_protocol, quic_span protocol, u8* out, usz cap) {
  u8              fs[128];
  quic_obuf       fsb         = quic_obuf_of(fs, sizeof fs);
  static const u8 authority[] = {'h', 'o', 's', 't'};
  CHECK(
      quic_h3req_enc_connect(quic_span_of(authority, sizeof authority), &fsb) ==
      1);
  if (want_protocol) {
    quic_qpack_field f = {quic_span_of((const u8*)":protocol", 9), protocol};
    usz              w = quic_qpack_literal_name_encode(
        quic_mspan_of(fs + fsb.len, sizeof(fs) - fsb.len), 0, &f);
    CHECK(w > 0);
    fsb.len += w;
  }

  u8        h3[160];
  quic_obuf h3b = quic_obuf_of(h3, sizeof h3);
  CHECK(
      quic_h3_frame_put(
          &h3b, QUIC_H3_FRAME_HEADERS, quic_span_of(fs, fsb.len)) > 0);

  quic_stream_frame sf = {0, 0, h3b.len, h3, 1};
  usz               w  = quic_frame_put_stream(out, cap, &sf);
  CHECK(w > 0);
  return w;
}

/* A CONNECT request carrying :protocol recovers it into r.protocol. */
static void test_connect_protocol_present(void) {
  static const u8 ws[] = {'w', 'e', 'b', 's', 'o', 'c', 'k', 'e', 't'};
  u8              stream[256];
  usz             n = build_connect_stream(
      1, quic_span_of(ws, sizeof ws), stream, sizeof stream);

  u8                   scratch[128];
  wired_h3reqdrive_req r = {0};
  CHECK(
      wired_h3reqdrive_recv_get(
          quic_span_of(stream, n), quic_mspan_of(scratch, sizeof scratch),
          &r) == 1);
  CHECK(r.protocol_len == sizeof ws);
  CHECK(r.protocol != 0);
  for (usz i = 0; i < sizeof ws; i++) CHECK(r.protocol[i] == ws[i]);
}

/* A CONNECT request without :protocol still parses, protocol_len stays 0. */
static void test_connect_protocol_absent(void) {
  u8  stream[256];
  usz n = build_connect_stream(0, quic_span_of(0, 0), stream, sizeof stream);

  u8                   scratch[128];
  wired_h3reqdrive_req r = {0};
  CHECK(
      wired_h3reqdrive_recv_get(
          quic_span_of(stream, n), quic_mspan_of(scratch, sizeof scratch),
          &r) == 1);
  CHECK(r.protocol == 0);
  CHECK(r.protocol_len == 0);
}

/* RFC 9220 3: a server MUST NOT accept :protocol unless it advertised
 * SETTINGS_ENABLE_CONNECT_PROTOCOL=1. */
static void test_connect_protocol_negotiation(void) {
  wired_h3reqdrive_req r = {0};
  r.protocol             = (const u8*)"websocket";
  r.protocol_len         = 9;
  CHECK(quic_h3_connect_protocol_ok(&r, 1) == 1); /* advertised: accepted */
  CHECK(quic_h3_connect_protocol_ok(&r, 0) == 0); /* not advertised: reject */

  r.protocol     = 0;
  r.protocol_len = 0;
  CHECK(quic_h3_connect_protocol_ok(&r, 0) == 1); /* no :protocol: always ok */
}

void test_connect(void) {
  test_connect_ok();
  test_connect_required();
  test_connect_forbidden();
  test_connect_encode_two_fields();
  test_connect_req_ok_rejects();
  test_connect_established();
  test_connect_state_forward();
  test_connect_protocol_present();
  test_connect_protocol_absent();
  test_connect_protocol_negotiation();
}
