#include "transport/conn/lifecycle/session/session_impl.h"

static int read_share(u8* pkt, usz pl, u8 peer_pub[32]);
static usz open_initial(session* s, u8* pkt, usz rn);
static int agree_dir(session* s, const u8 peer_pub[32], wired_span tr);
static int agree_both(session* client, session* server, wired_span tr);
static u32 my_addr(int is_server);
static u32 peer_addr(int is_server);
static usz open_1rtt(session* s, u8* pkt, usz rn);

/* Decode a received Initial's CRYPTO frame and extract the peer's share. */
static int read_share(u8* pkt, usz pl, u8 peer_pub[32]) {
  crypto_frame cf;
  u8           type;
  usz          body_len;
  if (frame_get_crypto(pkt + 18, pl, &cf) == 0) {
    return 0;
  }
  if (hs_parse(wired_span_of(cf.data, cf.length), &type, &body_len) == 0) {
    return 0;
  }
  return hs_peer_share(cf.data + 4, body_len, peer_pub);
}

/* Unprotect a received Initial of rn bytes in place; returns plaintext len. */
static usz open_initial(session* s, u8* pkt, usz rn) {
  if (rn == 0) {
    return 0;
  }
  protect_keys    k  = {&s->ikeys, &s->ihp};
  protect_open_io io = {wired_mspan_of(pkt, rn), 18, 14, 4, 1};
  return protect_open(&k, &io);
}

int session_accept(session* s) {
  u8         pkt[1200];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  usz rn = session_link_rx(s->link, &ob, (ipv4addrs){SESSION_CA, SESSION_SA});
  usz pl = open_initial(s, pkt, rn);
  if (pl == 0) {
    return 0;
  }
  if (!read_share(pkt, pl, s->peer_pub)) {
    return 0;
  }
  s->have_peer = 1;
  conn_step(&s->conn, CONN_EV_HS_PROGRESS);
  return 1;
}

/* Derive the server-direction 1-RTT keys both ends use, and the matching
 * header-protection cipher, into the session. RFC 7748 6.1: a low-order peer
 * key aborts the agreement (endpoint_agree returns 0). */
static int agree_dir(session* s, const u8 peer_pub[32], wired_span tr) {
  endpoint_peer p = {peer_pub, tr, 1};
  if (!endpoint_agree(&s->ep, &p)) {
    return 0;
  }
  aes128_init(&s->hshp, s->ep.hs_keys.hp);
  return 1;
}

/* Both ends derive the server-direction keys from the same ECDHE inputs. */
static int agree_both(session* client, session* server, wired_span tr) {
  if (!agree_dir(server, server->peer_pub, tr)) {
    return 0;
  }
  return agree_dir(client, server->ep.pub, tr);
}

int session_finish(session* client, session* server, wired_span transcript) {
  if (!server->have_peer) {
    return 0;
  }
  if (!agree_both(client, server, transcript)) {
    return 0;
  }
  conn_step(&client->conn, CONN_EV_HS_CONFIRMED);
  conn_step(&server->conn, CONN_EV_HS_CONFIRMED);
  return 1;
}

/* Our own IPv4 address on the link, by role. */
static u32 my_addr(int is_server) {
  return is_server ? SESSION_SA : SESSION_CA;
}

/* The peer's IPv4 address on the link, by role. */
static u32 peer_addr(int is_server) {
  return is_server ? SESSION_CA : SESSION_SA;
}

int session_send_stream(session* s, const session_msg* m) {
  u8           fr[1024];
  stream_frame sf = {
      .stream_id = m->stream_id,
      .offset    = 0,
      .length    = m->data.n,
      .data      = m->data.p,
      .fin       = m->fin};
  usz          fl = frame_put_stream(fr, sizeof(fr), &sf);
  protect_keys k  = {&s->ep.hs_keys, &s->hshp};
  return session_seal_tx(
      s, &k, 0x43, 7, wired_span_of(fr, fl), /* short-header form, pn 7 */
      (ipv4addrs){my_addr(s->is_server), peer_addr(s->is_server)});
}

/* Unprotect a received 1-RTT packet of rn bytes in place; plaintext len. */
static usz open_1rtt(session* s, u8* pkt, usz rn) {
  if (rn == 0) {
    return 0;
  }
  protect_keys    k  = {&s->ep.hs_keys, &s->hshp};
  protect_open_io io = {wired_mspan_of(pkt, rn), 18, 14, 4, 7};
  return protect_open(&k, &io);
}

int session_recv_stream(session* s, stream_frame* out) {
  wired_obuf ob = obuf_of(s->rxbuf, sizeof(s->rxbuf));
  usz        rn = session_link_rx(
      s->link, &ob,
      (ipv4addrs){peer_addr(s->is_server), my_addr(s->is_server)});
  usz pl = open_1rtt(s, s->rxbuf, rn);
  if (pl == 0) {
    return 0;
  }
  return frame_get_stream(s->rxbuf + 18, pl, out) != 0;
}
