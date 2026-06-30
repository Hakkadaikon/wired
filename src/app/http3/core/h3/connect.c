#include "app/http3/core/h3/connect.h"

/* CONNECT requires :method == CONNECT and :authority. */
static int connect_required(int has_method_connect, int has_authority) {
  return has_method_connect && has_authority;
}

/* CONNECT forbids :scheme and :path. */
static int connect_forbidden(int has_scheme, int has_path) {
  return has_scheme || has_path;
}

int quic_h3_connect_ok(
    int has_method_connect, int has_authority, int has_scheme, int has_path) {
  if (!connect_required(has_method_connect, has_authority)) return 0;
  if (connect_forbidden(has_scheme, has_path)) return 0;
  return 1;
}

/* All len octets of m equal want. */
static int cn_bytes_eq(const u8 *m, const u8 *want, usz len) {
  for (usz i = 0; i < len; i++)
    if (m[i] != want[i]) return 0;
  return 1;
}

/* :method value equals the 7 octets "CONNECT". */
static int method_is_connect(const u8 *m, usz len) {
  static const u8 want[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  if (!m || len != sizeof want) return 0;
  return cn_bytes_eq(m, want, sizeof want);
}

int quic_h3_connect_req_ok(const quic_h3reqdrive_req *r) {
  return quic_h3_connect_ok(
      method_is_connect(r->method, r->method_len), r->authority != 0,
      r->scheme != 0, r->path != 0);
}

int quic_h3_connect_established(u16 status) {
  return status >= 200 && status < 300;
}

void quic_h3_tunnel_init(quic_h3_tunnel *st) { *st = QUIC_H3_TUNNEL_REQ; }

void quic_h3_tunnel_validated(quic_h3_tunnel *st) {
  if (*st == QUIC_H3_TUNNEL_REQ) *st = QUIC_H3_TUNNEL_VALIDATED;
}

int quic_h3_tunnel_response(quic_h3_tunnel *st, u16 status) {
  if (*st != QUIC_H3_TUNNEL_VALIDATED) return 0;
  *st = quic_h3_connect_established(status) ? QUIC_H3_TUNNEL_ESTABLISHED
                                            : QUIC_H3_TUNNEL_FAILED;
  return *st == QUIC_H3_TUNNEL_ESTABLISHED;
}

int quic_h3_tunnel_relay(quic_h3_tunnel *st) {
  /* ponytail: state advances to RELAY to assert the tunnel is live; the raw
   * byte relay itself is out of SDK scope — payload moves over the existing
   * h3 DATA-frame path (appdata), driven by the application. */
  if (*st != QUIC_H3_TUNNEL_ESTABLISHED) return 0;
  *st = QUIC_H3_TUNNEL_RELAY;
  return 1;
}

void quic_h3_tunnel_close(quic_h3_tunnel *st) { *st = QUIC_H3_TUNNEL_CLOSED; }
