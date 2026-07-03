#include "transport/conn/lifecycle/endpoint/endpoint.h"

#include "test.h"
#include "transport/io/socket/net/ipv4.h"
#include "transport/io/socket/net/memlink.h"
#include "transport/io/socket/net/udp4.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/protect/protect/protect.h"

/* Wrap a QUIC packet in UDP+IPv4 and push it onto the link (no syscall). */
static usz tx(quic_memlink *l, const u8 *qpkt, usz qlen, u32 src, u32 dst) {
  u8            udp[1500], ip[20], frame[1520];
  quic_udp4meta meta = {{4433, 4433}, {src, dst}};
  quic_obuf     ub   = quic_obuf_of(udp, sizeof(udp));
  usz           un   = quic_udp4_build(&ub, &meta, quic_span_of(qpkt, qlen));
  quic_ipv4_build(
      ip, &(quic_ipv4_head){(u16)(20 + un), src, dst, QUIC_IP_PROTO_UDP});
  for (usz i = 0; i < 20; i++) frame[i] = ip[i];
  for (usz i = 0; i < un; i++) frame[20 + i] = udp[i];
  quic_memlink_send(l, frame, 20 + un);
  return 20 + un;
}

/* Pull a frame, verify IP/UDP, and copy out the QUIC payload. Returns len. */
static usz rx(quic_memlink *l, u8 *qpkt, usz cap, u32 src, u32 dst) {
  u8  frame[1520];
  usz fn = quic_memlink_recv(l, frame, sizeof(frame));
  usz un = fn - 20;
  if (fn == 0 || !quic_ipv4_check(frame)) return 0;
  if (!quic_udp4_check(
          quic_span_of(frame + 20, un), (quic_ipv4addrs){src, dst}))
    return 0;
  usz qlen = un - QUIC_UDP_HDR;
  for (usz i = 0; i < qlen && i < cap; i++)
    qpkt[i] = frame[20 + QUIC_UDP_HDR + i];
  return qlen;
}

/* Build an Initial carrying a ClientHello, protected with the client's
 * Initial keys, into out. Returns the protected length. */
static usz make_client_initial(
    quic_endpoint           *c,
    const quic_initial_keys *ik,
    const quic_aes128       *hp,
    u8                      *out,
    usz                      cap) {
  u8  hello[256], crypto[300], hdr[18];
  u8  rnd[32] = {0};
  usz hl      = quic_hs_build_hello(
      hello, sizeof(hello), QUIC_HS_CLIENT_HELLO, rnd, c->pub);
  quic_crypto_frame cf = {.offset = 0, .length = hl, .data = hello};
  usz               cl = quic_frame_put_crypto(crypto, sizeof(crypto), &cf);
  for (usz i = 0; i < 18; i++) hdr[i] = 0;
  hdr[0] = 0xc3;
  hdr[4] = 1;
  hdr[5] = 8;
  for (usz i = 0; i < 8; i++) hdr[6 + i] = c->dcid[i];
  hdr[17]                 = 1; /* packet number 1 */
  quic_protect_keys    k  = {ik, hp};
  quic_protect_seal_io io = {
      quic_span_of(hdr, 18),  14, 4, 1, quic_span_of(crypto, cl),
      quic_mspan_of(out, cap)};
  return quic_protect_seal(&k, &io);
}

/* Server receives the client Initial, unprotects, and extracts the share. */
static int server_read_initial(
    u8                      *pkt,
    usz                      plen,
    const quic_initial_keys *ik,
    const quic_aes128       *hp,
    u8                       peer_pub[32]) {
  quic_protect_keys    k  = {ik, hp};
  quic_protect_open_io io = {quic_mspan_of(pkt, plen), 18, 14, 4, 1};
  usz                  pl = quic_protect_open(&k, &io);
  quic_crypto_frame    cf;
  u8                   type;
  usz                  body_len;
  if (pl == 0 || quic_frame_get_crypto(pkt + 18, pl, &cf) == 0) return 0;
  if (quic_hs_parse(quic_span_of(cf.data, cf.length), &type, &body_len) == 0)
    return 0;
  return quic_hs_peer_share(cf.data + 4, body_len, peer_pub);
}

/* Full kernel-free handshake: client Initial over memlink -> server reads it,
 * both run X25519 + the key schedule, and end up with identical 1-RTT-able
 * handshake keys. Then a 1-RTT STREAM round-trips under those keys. */
static void test_endpoint_handshake(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  u8       cpriv[32], spriv[32];
  for (usz i = 0; i < 32; i++) {
    cpriv[i] = (u8)(i + 1);
    spriv[i] = (u8)(0x40 + i);
  }
  quic_endpoint cl, sv;
  quic_endpoint_init(&cl, cpriv, dcid);
  quic_endpoint_init(&sv, spriv, dcid);

  quic_initial_keys cik; /* client Initial keys (both sides derive) */
  quic_aes128       chp;
  quic_initial_derive(quic_span_of(dcid, 8), 0, &cik);
  quic_aes128_init(&chp, cik.hp);

  quic_memlink link;
  quic_memlink_init(&link);
  u32 ca = 0x0a000001, sa = 0x0a000002;

  /* client sends Initial(ClientHello) through the userspace stack */
  u8  qpkt[1200];
  usz qn = make_client_initial(&cl, &cik, &chp, qpkt, sizeof(qpkt));
  CHECK(qn != 0);
  tx(&link, qpkt, qn, ca, sa);

  /* server receives it with no syscall and recovers the client's share */
  u8  rxpkt[1200], peer_pub[32];
  usz rn = rx(&link, rxpkt, sizeof(rxpkt), ca, sa);
  CHECK(rn == qn);
  CHECK(server_read_initial(rxpkt, rn, &cik, &chp, peer_pub) == 1);
  for (usz i = 0; i < 32; i++) CHECK(peer_pub[i] == cl.pub[i]);

  /* both agree on the handshake secret from the same ECDHE inputs */
  const u8           tr[] = "transcript";
  quic_endpoint_peer pc   = {sv.pub, quic_span_of(tr, sizeof(tr)), 0};
  quic_endpoint_peer ps   = {peer_pub, quic_span_of(tr, sizeof(tr)), 1};
  quic_endpoint_agree(&cl, &pc);
  quic_endpoint_agree(&sv, &ps);
  /* client's view of the server direction == server's own keys */
  quic_initial_keys cl_sees_server;
  {
    u8 shared[32], hs[32];
    quic_x25519(shared, cl.priv, sv.pub);
    quic_tls_handshake_secret(shared, hs);
    quic_tls_handshake_keys(
        &(quic_handshake_keys_in){hs, quic_span_of(tr, sizeof(tr)), 1},
        &cl_sees_server);
  }
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++)
    CHECK(cl_sees_server.key[i] == sv.hs_keys.key[i]);

  /* 1-RTT STREAM data round-trips under the agreed (server) handshake keys */
  quic_aes128 shp;
  quic_aes128_init(&shp, sv.hs_keys.hp);
  u8                sframe[32], spkt[128];
  quic_stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8 *)"hello",
      .fin       = 1};
  usz sfl      = quic_frame_put_stream(sframe, sizeof(sframe), &sf);
  u8  shdr[18] = {0x43, 0, 0, 0, 1, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7};
  for (usz i = 0; i < 8; i++) shdr[6 + i] = dcid[i];
  quic_protect_keys    sk  = {&sv.hs_keys, &shp};
  quic_protect_seal_io sio = {
      quic_span_of(shdr, 18),           14, 4, 7, quic_span_of(sframe, sfl),
      quic_mspan_of(spkt, sizeof(spkt))};
  usz sp = quic_protect_seal(&sk, &sio);
  tx(&link, spkt, sp, sa, ca);

  u8                   crx[128];
  usz                  crn = rx(&link, crx, sizeof(crx), sa, ca);
  quic_protect_keys    ck2 = {&cl_sees_server, &shp};
  quic_protect_open_io oio = {quic_mspan_of(crx, crn), 18, 14, 4, 7};
  usz                  cpl = quic_protect_open(&ck2, &oio);
  CHECK(cpl != 0);
  quic_stream_frame got;
  CHECK(quic_frame_get_stream(crx + 18, cpl, &got) != 0);
  CHECK(got.stream_id == 4 && got.fin == 1 && got.length == 5);
  CHECK(got.data[0] == 'h' && got.data[4] == 'o');
}

void test_endpoint(void) { test_endpoint_handshake(); }
