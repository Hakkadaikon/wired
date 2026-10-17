#include "transport/conn/lifecycle/session/session_impl.h"

static int  env_ok(wired_span frame, ipv4addrs addrs);
static void copy_n(u8* dst, const u8* src, usz n);
static void fill_header(u8 hdr[18], u8 byte0, const u8 dcid[8], u8 pn_low);

/* Validate a received frame's IP+UDP envelope. Returns 1 if it checks out. */
static int env_ok(wired_span frame, ipv4addrs addrs) {
  if (frame.n == 0 || !ipv4_check(frame.p)) {
    return 0;
  }
  return udp4_check(wired_span_of(frame.p + 20, frame.n - 20), addrs);
}

/* Copy n bytes from src to dst. */
static void copy_n(u8* dst, const u8* src, usz n) {
  for (usz i = 0; i < n; i++) {
    dst[i] = src[i];
  }
}

/* Pull a frame, verify IP/UDP, copy out the QUIC payload. Returns its len. */
usz session_link_rx(memlink* l, wired_obuf* out, ipv4addrs addrs) {
  u8  frame[1520];
  usz fn = memlink_recv(l, frame, sizeof(frame));
  if (!env_ok(wired_span_of(frame, fn), addrs)) {
    return 0;
  }
  usz qlen = fn - 20 - UDP_HDR;
  usz n    = (qlen < out->cap) ? qlen : out->cap;
  copy_n(out->p, frame + 20 + UDP_HDR, n);
  return qlen;
}

/* Fill an 18-byte protected-packet header (byte0, version, DCID len, DCID,
 * then the 4-byte packet number at offset 14) for packet number pn. */
static void fill_header(u8 hdr[18], u8 byte0, const u8 dcid[8], u8 pn_low) {
  for (usz i = 0; i < 18; i++) {
    hdr[i] = 0;
  }
  hdr[0] = byte0;
  hdr[4] = 1; /* version 1 */
  hdr[5] = 8; /* DCID length */
  for (usz i = 0; i < 8; i++) {
    hdr[6 + i] = dcid[i];
  }
  hdr[17] = pn_low; /* low byte of the 4-byte packet number */
}

void session_init(session* s, const session_init_in* in) {
  endpoint_init(&s->ep, in->priv, in->dcid);
  conn_init(&s->conn);
  initial_derive(wired_span_of(in->dcid, 8), 0, VERSION_1, &s->ikeys);
  aes128_init(&s->ihp, s->ikeys.hp);
  s->link      = in->link;
  s->is_server = in->is_server;
  s->have_peer = 0;
  for (usz i = 0; i < 8; i++) {
    s->dcid[i] = in->dcid[i];
  }
}

/* Seal payload as packet number pn under header byte byte0 and push it
 * onto the link from/to addrs. Returns 0 if it does not fit. */
int session_seal_tx(
    session*            s,
    const protect_keys* k,
    u8                  byte0,
    u8                  pn,
    wired_span          payload,
    ipv4addrs           addrs) {
  u8 hdr[18], out[1200];
  fill_header(hdr, byte0, s->dcid, pn);
  protect_seal_io io = {wired_span_of(hdr, 18),          14, 4, pn, payload,
                        wired_mspan_of(out, sizeof(out))};
  usz             n  = protect_seal(k, &io);
  if (n == 0) {
    return 0;
  }
  return session_link_tx(s->link, wired_span_of(out, n), addrs);
}

int session_client_hello(session* s) {
  u8  hello[256], crypto[300];
  u8  rnd[32] = {0};
  usz hl =
      hs_build_hello(hello, sizeof(hello), HS_CLIENT_HELLO, rnd, s->ep.pub);
  crypto_frame cf = {.offset = 0, .length = hl, .data = hello};
  usz          cl = frame_put_crypto(crypto, sizeof(crypto), &cf);
  protect_keys k  = {&s->ikeys, &s->ihp};
  return session_seal_tx(
      s, &k, 0xc3, 1, wired_span_of(crypto, cl),
      (ipv4addrs){SESSION_CA, SESSION_SA});
}
