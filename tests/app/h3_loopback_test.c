#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/http3/server/srvwire/wire.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/client/client.h"
#include "tls/handshake/roles/server/server.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9001 4 / 5 / 5.1, RFC 9000 17.2, RFC 9114 4.1: real-AEAD-wire loopback.
 * A genuine server orchestrator (quic_server) is driven to FLIGHT_SENT, then a
 * client peer (sharing the server's key schedule, so seal-then-open across the
 * wire is identity per RFC 9001 5) seals its real Finished and GET into
 * AEAD-protected QUIC packets, ships them across a real 127.0.0.1 UDP socket,
 * and the server runs quic_srvloop_step on the bytes that came off the wire:
 *
 *   1. Initial datagram delivery: the client's real protected Initial reaches a
 *      bound server socket (RFC 9000 14.1 padding to 1200).
 *   2. real-wire confirmation: a srvwire-sealed client Finished crosses the
 *      socket and quic_srvloop_step opens it, confirms the server, and seals a
 *      1-RTT HANDSHAKE_DONE that the peer opens with SERVER_AP.
 *   3. real-wire GET -> 200: a 1-RTT GET crosses the socket and the step seals
 * a 200 the peer opens with SERVER_AP.
 *
 * Sockets may be forbidden in a sandbox; a failed open/bind is a benign skip,
 * matching udptransport_test. The buffer-path equivalent (no socket) is covered
 * by srvloop_test's full round trip. */

/* RFC 5280 4.1: minimal Ed25519 end-entity cert carrying pub in its SPKI. */
static usz lb_ed_cert(u8 *out, const u8 pub[32]) {
  static const u8 head[] = {
      0x30, 0x48, 0x30, 0x3c, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01,
      0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x2a,
      0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
  };
  static const u8 tail[] = {
      0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x01, 0x00,
  };
  usz off = 0, i;
  for (i = 0; i < sizeof(head); i++) out[off++] = head[i];
  for (i = 0; i < 32; i++) out[off++] = pub[i];
  for (i = 0; i < sizeof(tail); i++) out[off++] = tail[i];
  return off;
}

static const u8 g_scid[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

struct lb_fix {
  quic_server  s;
  quic_srvloop l;
  u8           ch[512];
  usz          ch_len;
  u8           sh[256];
  usz          sh_len;
  u8           flight[2048];
  usz          flight_len;
  u8           srv_random[32];
  u8           cli_priv[32];
  u8           sh_pub[32];
  u8           cli_fin[64];
  usz          cli_fin_len;
};

static void lb_make_client_hello(struct lb_fix *f) {
  static const u8 tp[1] = {0};
  u8              cli_pub[32];
  for (usz i = 0; i < 32; i++) {
    f->cli_priv[i]   = (u8)(i + 1);
    f->srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, f->cli_priv);
  f->ch_len = quic_tls_client_hello(
      f->ch, sizeof(f->ch), f->srv_random, cli_pub, 0, 0, tp, sizeof(tp));
}

/* Bring the server to FLIGHT_SENT (Handshake keys derived) and init the loop.
 */
static void lb_drive_to_flight(struct lb_fix *f) {
  u8        srv_priv[32], srv_pub[32], cert_seed[32], cert_pub[32];
  static u8 cert[128];
  usz       cert_len;
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  CHECK(quic_ed25519_keypair(cert_seed, cert_pub));
  cert_len = lb_ed_cert(cert, cert_pub);

  quic_server_init(&f->s, srv_priv, srv_pub, cert_seed, cert, cert_len);
  CHECK(quic_server_set_cids(&f->s, g_scid, 6, g_scid, 6) == 1);
  CHECK(quic_srvloop_init(&f->l, g_scid, 6) == 1);
  CHECK(quic_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
  CHECK(
      quic_server_build_flight(
          &f->s, f->srv_random, f->sh, sizeof(f->sh), &f->sh_len, f->flight,
          sizeof(f->flight), &f->flight_len) == 1);
  CHECK(f->s.phase == QUIC_SERVER_HS_FLIGHT_SENT);
}

/* RFC 8446 4.4.4: compute the genuine client Finished from the transcript. */
static void lb_make_client_finished(struct lb_fix *f) {
  u16             cipher, version;
  u8              hs[32], c_traffic[32], th[32];
  quic_transcript tr;
  usz             off;
  CHECK(quic_tls_parse_server_hello(
      f->sh, f->sh_len, f->sh_pub, &cipher, &version));
  {
    u8 shared[32];
    quic_x25519(shared, f->cli_priv, f->sh_pub);
    quic_tls_handshake_secret(shared, hs);
  }
  quic_transcript_init(&tr);
  quic_transcript_add(&tr, f->ch, f->ch_len);
  quic_transcript_add(&tr, f->sh, f->sh_len);
  quic_transcript_hash(&tr, th);
  quic_hkdf_expand_label(hs, "c hs traffic", 12, th, 32, c_traffic, 32);
  quic_transcript_add(&tr, f->flight, f->flight_len);
  quic_transcript_hash(&tr, th);
  off = quic_hs_begin(f->cli_fin, sizeof(f->cli_fin), QUIC_HS_FINISHED);
  quic_tls_finished_verify_data(c_traffic, th, f->cli_fin + off);
  f->cli_fin_len = off + QUIC_TLS_VERIFY_DATA;
  quic_hs_finish(f->cli_fin, f->cli_fin_len);
}

/* Client peer: seal a Handshake CRYPTO flight toward the server with the
 * peer-direction CLIENT_HS key (the server opens with it). */
static usz lb_seal_handshake(
    struct lb_fix *f, const u8 *msg, usz mlen, u8 *pkt, usz cap) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  /* ack_pn 0: also acknowledge the server's Handshake PN 0, exercising the
   * server open path against a flight that carries a trailing ACK frame. */
  CHECK(quic_srvwire_seal_handshake(
      k, &hp, f->s.sdrv.iscid, f->s.sdrv.iscid_len, g_scid, 6, 0, 0, msg, mlen,
      pkt, cap, &total));
  return total;
}

/* Client peer: seal a 1-RTT STREAM payload toward the server with CLIENT_AP. */
static usz lb_seal_onertt(
    struct lb_fix *f, const u8 *pl, usz pln, u8 *pkt, usz cap) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_AP, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  CHECK(quic_hspkt_onertt_build(
      k, &hp, f->s.sdrv.iscid, f->s.sdrv.iscid_len, 0, pl, pln, pkt, cap,
      &total));
  return total;
}

/* Client peer: open a server 1-RTT packet with the peer SERVER_AP key. */
static int lb_open_onertt(
    struct lb_fix *f, u8 *pkt, usz len, const u8 **pl, usz *pll) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_SERVER_AP, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  return quic_hspkt_onertt_open(k, &hp, pkt, len, 6, 0, pl, pll);
}

/* A bound server socket and a client socket, both on 127.0.0.1. Returns 1 with
 * the fds, or 0 (benign skip) if the sandbox forbids sockets. */
static int lb_open_sockets(i64 *sfd, i64 *cfd, quic_sockaddr_in *srv) {
  *sfd = quic_udp_socket();
  if (*sfd < 0) return 0;
  quic_udp_addr(srv, 4435, 127, 0, 0, 1);
  if (quic_udp_bind(*sfd, srv) < 0) {
    quic_udp_close(*sfd);
    return 0;
  }
  *cfd = quic_udp_socket();
  if (*cfd < 0) {
    quic_udp_close(*sfd);
    return 0;
  }
  return 1;
}

/* Ship `pkt` from client to server and run one srvloop_step on what arrives.
 * Returns the step result; *out_len holds the sealed reply length. */
static int lb_wire_step(
    struct lb_fix          *f,
    i64                     cfd,
    i64                     sfd,
    const quic_sockaddr_in *srv,
    const u8               *pkt,
    usz                     n,
    u8                     *out,
    usz                     cap,
    usz                    *out_len) {
  quic_sockaddr_in from;
  u8               rx[1500];
  i64              r;
  CHECK(quic_udp_send(cfd, srv, pkt, n) == (i64)n);
  r = quic_udp_recvfrom(sfd, rx, sizeof rx, &from);
  CHECK(r == (i64)n);
  return quic_srvloop_step(&f->l, &f->s, rx, (usz)r, out, cap, out_len);
}

/* (1) Loopback: the client's real protected Initial reaches a bound server
 * socket, padded to 1200 (RFC 9000 14.1). */
static void test_loopback_initial_datagram(void) {
  quic_client      c;
  quic_sockaddr_in srv, from;
  u8               priv[32], pub[32], pkt[1500], dg[1500];
  usz              total = 0;
  i64              sfd, n;

  sfd = quic_udp_socket();
  if (sfd < 0) return; /* sandbox: no sockets */
  quic_udp_addr(&srv, 4434, 127, 0, 0, 1);
  if (quic_udp_bind(sfd, &srv) < 0) {
    quic_udp_close(sfd);
    return;
  }

  for (usz i = 0; i < 32; i++) priv[i] = (u8)(7 + i);
  quic_x25519_base(pub, priv);
  quic_tlsdriver_init(&c.tls, priv, pub, 0);
  CHECK(
      quic_client_build_initial_wire(
          &c, g_scid, 6, g_scid, 6, 0, pkt, sizeof pkt, &total) == 1);
  CHECK(total == 1200); /* RFC 9000 14.1 padding */

  {
    i64 cfd = quic_udp_socket();
    if (cfd < 0) {
      quic_udp_close(sfd);
      return;
    }
    CHECK(quic_udp_send(cfd, &srv, pkt, total) == (i64)total);
    n = quic_udp_recvfrom(sfd, dg, sizeof dg, &from);
    CHECK(n == 1200);
    CHECK((dg[0] & 0x80) != 0); /* long header (RFC 9000 17.2) */
    quic_udp_close(cfd);
  }
  quic_udp_close(sfd);
}

/* (2)+(3) Real-AEAD-wire: a srvwire-sealed Finished and a 1-RTT GET cross a
 * real UDP socket; quic_srvloop_step opens them off the wire, confirms, and
 * seals a HANDSHAKE_DONE and a 200 the peer opens with SERVER_AP. */
static void test_loopback_wire_confirm_and_get(void) {
  struct lb_fix    f;
  quic_sockaddr_in srv;
  i64              sfd, cfd;
  u8               cpkt[1300], out[1300], get[512];
  usz              clen, out_len = 0, glen;
  const u8        *pl;
  usz              pll;

  if (!lb_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: benign skip */

  lb_make_client_hello(&f);
  lb_drive_to_flight(&f);
  lb_make_client_finished(&f);

  /* Finished over the wire -> confirmed + a coalesced reply: a Handshake ACK
   * (RFC 9000 13.2.1) ahead of a 1-RTT packet carrying SETTINGS +
   * HANDSHAKE_DONE (RFC 9114 6.2.1 / RFC 9000 19.20). */
  clen = lb_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      lb_wire_step(&f, cfd, sfd, &srv, cpkt, clen, out, sizeof out, &out_len) ==
      1);
  CHECK(quic_server_is_confirmed(&f.s) == 1);
  {
    const u8         *pkts[4];
    usz               offs[4], lens[4];
    quic_stream_frame sf;
    usz np = quic_udploop_split(out, out_len, pkts, offs, lens, 4);
    CHECK(np == 2);
    CHECK((out[offs[0]] & 0x80) != 0); /* long-header Handshake ACK */
    CHECK(lb_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
    CHECK(quic_frame_get_stream(pl, pll, &sf) > 0 && sf.stream_id == 3);
    CHECK(pl[pll - 1] == 0x1e); /* trailing HANDSHAKE_DONE */
  }

  /* GET over the wire -> 200 sealed back, opened by the peer. */
  CHECK(quic_h3reqdrive_send_get(
      0, (const u8 *)"/", 1, (const u8 *)"h", 1, get, sizeof get, &glen));
  clen    = lb_seal_onertt(&f, get, glen, cpkt, sizeof cpkt);
  out_len = 0;
  CHECK(
      lb_wire_step(&f, cfd, sfd, &srv, cpkt, clen, out, sizeof out, &out_len) ==
      1);
  CHECK(out_len > 0);
  CHECK(lb_open_onertt(&f, out, out_len, &pl, &pll) == 1);
  {
    u16       status    = 0;
    const u8 *rbody     = 0;
    usz       rbody_len = 0;
    CHECK(quic_h3conn_recv_response(pl, pll, &status, &rbody, &rbody_len));
    CHECK(status == 200); /* RFC 9114 4.1 */
  }
  quic_udp_close(cfd);
  quic_udp_close(sfd);
}

void test_h3_loopback(void) {
  test_loopback_initial_datagram();
  test_loopback_wire_confirm_and_get();
}
