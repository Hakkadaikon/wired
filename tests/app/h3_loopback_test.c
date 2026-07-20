#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/http3/server/srvwire/wire.h"
#include "realchain_golden.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/client/client.h"
#include "tls/handshake/roles/client/clientwire.h"
#include "tls/handshake/roles/server/server.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/conn/loop/crecv/message.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/version/version/version.h"

/* RFC 9001 4 / 5 / 5.1, RFC 9000 17.2, RFC 9114 4.1: real-AEAD-wire loopback.
 * A genuine server orchestrator (wired_server) is driven to FLIGHT_SENT, then a
 * client peer (sharing the server's key schedule, so seal-then-open across the
 * wire is identity per RFC 9001 5) seals its real Finished and GET into
 * AEAD-protected QUIC packets, ships them across a real 127.0.0.1 UDP socket,
 * and the server runs wired_srvloop_step on the bytes that came off the wire:
 *
 *   1. Initial datagram delivery: the client's real protected Initial reaches a
 *      bound server socket (RFC 9000 14.1 padding to 1200).
 *   2. real-wire confirmation: a srvwire-sealed client Finished crosses the
 *      socket and wired_srvloop_step opens it, confirms the server, and seals a
 *      1-RTT HANDSHAKE_DONE that the peer opens with SERVER_AP.
 *   3. real-wire GET -> 200: a 1-RTT GET crosses the socket and the step seals
 * a 200 the peer opens with SERVER_AP.
 *
 * Sockets may be forbidden in a sandbox; a failed open/bind is a benign skip,
 * matching udptransport_test. The buffer-path equivalent (no socket) is covered
 * by srvloop_test's full round trip. */

static const u8 g_scid[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

struct lb_fix {
  wired_server  s;
  wired_srvloop l;
  u8            ch[512];
  usz           ch_len;
  u8            sh[256];
  usz           sh_len;
  u8            flight[2048];
  usz           flight_len;
  u8            srv_random[32];
  u8            cli_priv[32];
  u8            sh_pub[32];
  u8            cli_fin[64];
  usz           cli_fin_len;
};

static void lb_make_client_hello(struct lb_fix* f) {
  static const u8 tp[1] = {0};
  u8              cli_pub[32];
  for (usz i = 0; i < 32; i++) {
    f->cli_priv[i]   = (u8)(i + 1);
    f->srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, f->cli_priv);
  f->ch_len = quic_tls_client_hello(
      &(quic_clienthello_in){
          f->srv_random, cli_pub, quic_span_of(0, 0),
          quic_span_of(tp, sizeof(tp))},
      &(quic_obuf){f->ch, sizeof(f->ch), 0});
}

/* Bring the server to FLIGHT_SENT (Handshake keys derived) and init the loop.
 */
static void lb_drive_to_flight(struct lb_fix* f) {
  u8 srv_priv[32], srv_pub[32], cert_seed[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  wired_server_init_in sin   = {srv_priv, srv_pub, cert_seed, 0, 0, 0, 0, 0};
  quic_obuf            sh_ob = quic_obuf_of(f->sh, sizeof(f->sh));
  quic_obuf            fl_ob = quic_obuf_of(f->flight, sizeof(f->flight));
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  wired_server_init(&f->s, &sin);
  CHECK(
      wired_server_set_cids(
          &f->s, quic_span_of(g_scid, 6), quic_span_of(g_scid, 6)) == 1);
  CHECK(wired_srvloop_init(&f->l, g_scid, 6) == 1);
  CHECK(wired_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
  CHECK(wired_server_build_flight(&f->s, f->srv_random, &fo) == 1);
  f->sh_len     = sh_ob.len;
  f->flight_len = fl_ob.len;
  CHECK(f->s.phase == WIRED_SERVER_HS_FLIGHT_SENT);
}

/* RFC 8446 4.4.4: compute the genuine client Finished from the transcript. */
static void lb_make_client_finished(struct lb_fix* f) {
  quic_serverhello_out sh;
  u8                   hs[32], c_traffic[32], th[32];
  quic_transcript      tr;
  usz                  off;
  CHECK(quic_tls_parse_server_hello(
      quic_span_of(f->sh, f->sh_len), f->sh_pub, &sh));
  {
    u8 shared[32];
    quic_x25519(shared, f->cli_priv, f->sh_pub);
    quic_tls_handshake_secret(shared, hs);
  }
  quic_transcript_init(&tr);
  quic_transcript_add(&tr, f->ch, f->ch_len);
  quic_transcript_add(&tr, f->sh, f->sh_len);
  quic_transcript_hash(&tr, th);
  quic_hkdf_label chl = {"c hs traffic", 12, {th, 32}};
  quic_hkdf_expand_label(hs, &chl, quic_mspan_of(c_traffic, 32));
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
    struct lb_fix* f, const u8* msg, usz mlen, u8* pkt, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  quic_obuf                ob = {pkt, cap, 0};
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  /* ack_pn 0: also acknowledge the server's Handshake PN 0, exercising the
   * server open path against a flight that carries a trailing ACK frame. */
  quic_srvwire_seal_in in = {
      quic_span_of((const u8*)0, 0),
      quic_span_of(f->s.sdrv.iscid, f->s.sdrv.iscid_len),
      quic_span_of(g_scid, 6),
      0,
      0,
      quic_span_of(msg, mlen),
      0};
  quic_protect_keys pk = {k, &hp};
  CHECK(quic_srvwire_seal_handshake(&pk, &in, &ob));
  return ob.len;
}

/* Client peer: seal a 1-RTT STREAM payload toward the server with CLIENT_AP. */
static usz lb_seal_onertt(
    struct lb_fix* f, const u8* pl, usz pln, u8* pkt, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_AP, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys      pk = {k, &hp};
  quic_hspkt_onertt_desc d  = {
      quic_span_of(f->s.sdrv.iscid, f->s.sdrv.iscid_len), 0,
      quic_span_of(pl, pln), 0};
  quic_obuf o = quic_obuf_of(pkt, cap);
  CHECK(quic_hspkt_onertt_build(&pk, &d, &o));
  total = o.len;
  return total;
}

/* Client peer: open a server 1-RTT packet with the peer SERVER_AP key. */
static int lb_open_onertt(
    struct lb_fix* f, u8* pkt, usz len, const u8** pl, usz* pll) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_SERVER_AP, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys           pk = {k, &hp};
  quic_hspkt_onertt_open_desc d  = {quic_mspan_of(pkt, len), 6, 0};
  quic_span                   v;
  if (!quic_hspkt_onertt_open(&pk, &d, &v)) return 0;
  *pl  = v.p;
  *pll = v.n;
  return 1;
}

/* A bound server socket and a client socket, both on 127.0.0.1. Returns 1 with
 * the fds, or 0 (benign skip) if the sandbox forbids sockets. */
static int lb_open_sockets(i64* sfd, i64* cfd, quic_sockaddr* srv) {
  *sfd = wired_udp_socket();
  if (*sfd < 0) return 0;
  wired_udp_addr(srv, 4435, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(*sfd, srv) < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  *cfd = wired_udp_socket();
  if (*cfd < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  return 1;
}

/* Ship `pkt` from client to server and run one srvloop_step on what arrives.
 * Returns the step result; *out_len holds the sealed reply length. */
static int lb_wire_step(
    struct lb_fix*       f,
    i64                  cfd,
    i64                  sfd,
    const quic_sockaddr* srv,
    const u8*            pkt,
    usz                  n,
    quic_obuf*           out) {
  quic_sockaddr from;
  u8            rx[1500];
  i64           r;
  CHECK(wired_udp_send(cfd, srv, quic_span_of(pkt, n)) == (i64)n);
  r = wired_udp_recvfrom(sfd, quic_mspan_of(rx, sizeof rx), &from);
  CHECK(r == (i64)n);
  return wired_srvloop_step(
      &(wired_srvloop_conn){&f->l, &f->s}, quic_mspan_of(rx, (usz)r), out);
}

/* (1) Loopback: the client's real protected Initial reaches a bound server
 * socket, padded to 1200 (RFC 9000 14.1). */
static void test_loopback_initial_datagram(void) {
  quic_client   c;
  quic_sockaddr srv, from;
  u8            priv[32], pub[32], pkt[1500], dg[1500];
  usz           total = 0;
  i64           sfd, n;

  sfd = wired_udp_socket();
  if (sfd < 0) return; /* sandbox: no sockets */
  wired_udp_addr(&srv, 4434, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(sfd, &srv) < 0) {
    wired_udp_close(sfd);
    return;
  }

  for (usz i = 0; i < 32; i++) priv[i] = (u8)(7 + i);
  quic_x25519_base(pub, priv);
  quic_tlsdriver_init(&c.tls, priv, pub, 0);
  {
    quic_clientwire_hdr_in hdr = {
        quic_span_of(g_scid, 6), quic_span_of(g_scid, 6), 0};
    quic_obuf ob = quic_obuf_of(pkt, sizeof pkt);
    CHECK(quic_client_build_initial_wire(&c, &hdr, &ob) == 1);
    total = ob.len;
  }
  CHECK(total == 1200); /* RFC 9000 14.1 padding */

  {
    i64 cfd = wired_udp_socket();
    if (cfd < 0) {
      wired_udp_close(sfd);
      return;
    }
    CHECK(wired_udp_send(cfd, &srv, quic_span_of(pkt, total)) == (i64)total);
    n = wired_udp_recvfrom(sfd, quic_mspan_of(dg, sizeof dg), &from);
    CHECK(n == 1200);
    CHECK((dg[0] & 0x80) != 0); /* long header (RFC 9000 17.2) */
    wired_udp_close(cfd);
  }
  wired_udp_close(sfd);
}

/* (2)+(3) Real-AEAD-wire: a srvwire-sealed Finished and a 1-RTT GET cross a
 * real UDP socket; wired_srvloop_step opens them off the wire, confirms, and
 * seals a HANDSHAKE_DONE and a 200 the peer opens with SERVER_AP. */
static void test_loopback_wire_confirm_and_get(void) {
  struct lb_fix f;
  quic_sockaddr srv;
  i64           sfd, cfd;
  u8            cpkt[1300], out[1300], get[512];
  usz           clen, glen;
  quic_obuf     ob = {out, sizeof out, 0};
  const u8*     pl;
  usz           pll;

  if (!lb_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: benign skip */

  lb_make_client_hello(&f);
  lb_drive_to_flight(&f);
  lb_make_client_finished(&f);

  /* Finished over the wire -> confirmed + a coalesced reply: a Handshake ACK
   * (RFC 9000 13.2.1) ahead of a 1-RTT packet carrying SETTINGS +
   * HANDSHAKE_DONE (RFC 9114 6.2.1 / RFC 9000 19.20). */
  clen = lb_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(lb_wire_step(&f, cfd, sfd, &srv, cpkt, clen, &ob) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  {
    const u8*         pkts[4];
    usz               offs[4], lens[4];
    quic_pktlist      plist = {pkts, offs, lens, 4};
    quic_stream_frame sf;
    usz np = quic_udploop_split(quic_span_of(out, ob.len), &plist);
    CHECK(np == 2);
    CHECK((out[offs[0]] & 0x80) != 0); /* long-header Handshake ACK */
    CHECK(lb_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
    CHECK(quic_frame_get_stream(pl, pll, &sf) > 0 && sf.stream_id == 3);
    CHECK(pl[pll - 1] == 0x1e); /* trailing HANDSHAKE_DONE */
  }

  /* GET over the wire -> 200 sealed back, opened by the peer. */
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  clen = lb_seal_onertt(&f, get, glen, cpkt, sizeof cpkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  CHECK(lb_wire_step(&f, cfd, sfd, &srv, cpkt, clen, &ob) == 1);
  CHECK(ob.len > 0);
  CHECK(lb_open_onertt(&f, out, ob.len, &pl, &pll) == 1);
  {
    quic_h3conn_resp resp_out = {0};
    CHECK(quic_h3conn_recv_response(quic_span_of(pl, pll), &resp_out));
    CHECK(resp_out.status == 200); /* RFC 9114 4.1 */
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* Fill a wired_srvboot_id with the same fixed identity lb_drive_to_flight uses,
 * into caller-owned key buffers. */
static void sb_make_id(
    wired_srvboot_id* id, u8 priv[32], u8 pub[32], u8 seed[32], u8 rnd[32]) {
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x40 + i);
    seed[i] = (u8)(0x80 + i);
    rnd[i]  = (u8)(0xa0 + i);
  }
  quic_x25519_base(pub, priv);
  id->priv                    = priv;
  id->pub                     = pub;
  id->cert_seed               = seed;
  id->scid                    = g_scid;
  id->scid_len                = 6;
  id->random                  = rnd;
  id->chain                   = 0;
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 0;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
  id->retry_odcid             = 0;
  id->retry_odcid_len         = 0;
  id->ticket_key              = 0;
}

/* wired_srvboot_accept cold-starts a server from a real client Initial
 * datagram (built in-buffer, no socket) and seals two reply datagrams, each
 * fitting the same 1500-byte buffers production (srvrun) sends from. */
static void test_srvboot_accept(void) {
  quic_client      c;
  wired_server     s;
  wired_srvloop    l;
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], cpriv[32], cpub[32];
  u8               dg[1500], ini[1500], hs[1500];
  usz              total = 0;
  quic_obuf        iob   = {ini, sizeof ini, 0};
  quic_obuf        hob   = {hs, sizeof hs, 0};

  for (usz i = 0; i < 32; i++) cpriv[i] = (u8)(7 + i);
  quic_x25519_base(cpub, cpriv);
  quic_tlsdriver_init(&c.tls, cpriv, cpub, 0);
  {
    quic_clientwire_hdr_in hdr = {
        quic_span_of(g_scid, 6), quic_span_of(g_scid, 6), 0};
    quic_obuf ob = quic_obuf_of(dg, sizeof dg);
    CHECK(quic_client_build_initial_wire(&c, &hdr, &ob) == 1);
    total = ob.len;
  }

  wired_srvboot_conn conn = {&s, &l};
  wired_srvboot_in   in;
  wired_srvboot_out  out = {&iob, &hob, {0}, 0, 0};
  sb_make_id(&id, priv, pub, seed, rnd);
  in = (wired_srvboot_in){&id, quic_mspan_of(dg, total)};
  CHECK(wired_srvboot_accept(&conn, &in, &out) == 1);
  CHECK(s.phase == WIRED_SERVER_HS_FLIGHT_SENT);
  /* RFC 9000 14.1: the ack-eliciting server Initial datagram is padded to at
   * least 1200 bytes; both datagrams fit a 1500-byte MTU. A small self-signed
   * flight still fits one Handshake datagram (no split). */
  CHECK(iob.len >= 1200);
  CHECK(iob.len <= 1500);
  CHECK(hob.len > 0);
  CHECK(hob.len <= 1500);
  CHECK(out.dgram_count == 1);
  CHECK(out.dgram_len[0] == hob.len);
  CHECK(l.hs_tx_pn == 1); /* next Handshake send continues after the flight */
  CHECK((ini[0] & 0x80) != 0);   /* long-header ServerHello Initial */
  CHECK((ini[0] & 0x30) == 0);   /* Initial type bits (RFC 9000 17.2) */
  CHECK((hs[0] & 0x80) != 0);    /* long-header Handshake packet */
  CHECK((hs[0] & 0x30) == 0x20); /* Handshake type bits (RFC 9000 17.2) */

  /* wired_srvboot_is_initial classifies the datagram; a short one is rejected.
   */
  CHECK(wired_srvboot_is_initial(dg, total) == 1);
}

/* Run wired_srvboot_accept on a client Initial built with the given DCID and
 * SCID, filling out's reply datagrams. */
static void sb_accept_cids(
    quic_span          dcid,
    quic_span          scid,
    wired_srvboot_out* out,
    wired_server*      s,
    wired_srvloop*     l) {
  quic_client      c;
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], cpriv[32], cpub[32];
  u8               dg[1500];
  usz              total = 0;
  for (usz i = 0; i < 32; i++) cpriv[i] = (u8)(7 + i);
  quic_x25519_base(cpub, cpriv);
  quic_tlsdriver_init(&c.tls, cpriv, cpub, 0);
  {
    quic_clientwire_hdr_in hdr = {dcid, scid, 0};
    quic_obuf              ob  = quic_obuf_of(dg, sizeof dg);
    CHECK(quic_client_build_initial_wire(&c, &hdr, &ob) == 1);
    total = ob.len;
  }
  wired_srvboot_conn conn = {s, l};
  wired_srvboot_in   in;
  sb_make_id(&id, priv, pub, seed, rnd);
  in = (wired_srvboot_in){&id, quic_mspan_of(dg, total)};
  CHECK(wired_srvboot_accept(&conn, &in, out) == 1);
}

/* The reply datagram's header DCID equals want (RFC 9000 7.2). */
static void sb_check_hdr_dcid(quic_span dg, quic_span want) {
  wired_header h;
  CHECK(wired_header_parse(dg.p, dg.n, &h) != 0);
  CHECK(h.dcid_len == want.n);
  for (usz i = 0; i < want.n; i++) CHECK(h.dcid[i] == want.p[i]);
}

/* RFC 9000 7.2 / 17.2: the server addresses every reply to the client's SCID.
 * The client's original DCID only seeds the Initial keys (RFC 9001 5.2), and
 * the server's own SCID goes in the reply's SCID field -- neither belongs in
 * the reply's DCID. A client whose DCID and SCID are distinct values catches
 * either mix-up; a same-value client (as the accept test above uses) cannot.
 * A real browser silently discards a reply addressed to a CID it does not
 * own, so this mix-up presents as a handshake that goes completely
 * unanswered. */
static void test_srvboot_reply_dcid_is_client_scid(void) {
  static const u8   cli_dcid[8] = {0x38, 0x6f, 0xd3, 0x6a,
                                   0x70, 0x8d, 0x3c, 0xab};
  static const u8   cli_scid[5] = {0xc1, 0x15, 0xc1, 0xd5, 0x01};
  wired_server      s;
  wired_srvloop     l;
  u8                ini[1500], hs[1500];
  quic_obuf         iob = {ini, sizeof ini, 0};
  quic_obuf         hob = {hs, sizeof hs, 0};
  wired_srvboot_out out = {&iob, &hob, {0}, 0, 0};
  sb_accept_cids(
      quic_span_of(cli_dcid, 8), quic_span_of(cli_scid, 5), &out, &s, &l);
  sb_check_hdr_dcid(quic_span_of(ini, iob.len), quic_span_of(cli_scid, 5));
  sb_check_hdr_dcid(quic_span_of(hs, hob.len), quic_span_of(cli_scid, 5));
}

/* Chrome sends a zero-length SCID (it routes replies by address); the reply
 * DCID must then be zero-length as well (RFC 9000 7.2). */
static void test_srvboot_reply_dcid_empty_client_scid(void) {
  static const u8   cli_dcid[8] = {0x11, 0x22, 0x33, 0x44,
                                   0x55, 0x66, 0x77, 0x88};
  wired_server      s;
  wired_srvloop     l;
  u8                ini[1500], hs[1500];
  quic_obuf         iob = {ini, sizeof ini, 0};
  quic_obuf         hob = {hs, sizeof hs, 0};
  wired_srvboot_out out = {&iob, &hob, {0}, 0, 0};
  sb_accept_cids(
      quic_span_of(cli_dcid, 8), quic_span_of((const u8*)0, 0), &out, &s, &l);
  sb_check_hdr_dcid(quic_span_of(ini, iob.len), quic_span_of((const u8*)0, 0));
  sb_check_hdr_dcid(quic_span_of(hs, hob.len), quic_span_of((const u8*)0, 0));
}

/* A datagram that is not a valid Initial is refused (no flight produced). */
static void test_srvboot_rejects_non_initial(void) {
  wired_server     s;
  wired_srvloop    l;
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8 garbage[8] = {0x40, 1, 2, 3, 4, 5, 6, 7}; /* short header, not Initial */
  u8 ini[1500], hs[1500];
  quic_obuf          iob  = {ini, sizeof ini, 0};
  quic_obuf          hob  = {hs, sizeof hs, 0};
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0, 0};
  wired_srvboot_conn conn = {&s, &l};
  wired_srvboot_in   in;
  sb_make_id(&id, priv, pub, seed, rnd);
  in = (wired_srvboot_in){&id, quic_mspan_of(garbage, sizeof garbage)};
  CHECK(wired_srvboot_is_initial(garbage, sizeof garbage) == 0);
  CHECK(wired_srvboot_accept(&conn, &in, &out) == 0);
}

/* The server Initial acknowledges the packet number the client Initial
 * actually carried (a retransmitted Initial arrives with pn > 0), not a
 * hardcoded 0 (RFC 9000 13.2.1). */
static void test_srvboot_acks_actual_initial_pn(void) {
  quic_client        c;
  wired_server       s;
  wired_srvloop      l;
  wired_srvboot_id   id;
  u8                 priv[32], pub[32], seed[32], rnd[32], cpriv[32], cpub[32];
  u8                 dg[1500], ini[1500], hs[1500];
  quic_obuf          iob  = {ini, sizeof ini, 0};
  quic_obuf          hob  = {hs, sizeof hs, 0};
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0, 0};
  wired_srvboot_conn conn = {&s, &l};
  wired_srvboot_in   in;
  usz                total = 0;
  for (usz i = 0; i < 32; i++) cpriv[i] = (u8)(7 + i);
  quic_x25519_base(cpub, cpriv);
  quic_tlsdriver_init(&c.tls, cpriv, cpub, 0);
  {
    quic_clientwire_hdr_in hdr = {
        quic_span_of(g_scid, 6), quic_span_of(g_scid, 6), 2};
    quic_obuf ob = quic_obuf_of(dg, sizeof dg);
    CHECK(quic_client_build_initial_wire(&c, &hdr, &ob) == 1);
    total = ob.len;
  }
  sb_make_id(&id, priv, pub, seed, rnd);
  in = (wired_srvboot_in){&id, quic_mspan_of(dg, total)};
  CHECK(wired_srvboot_accept(&conn, &in, &out) == 1);
  CHECK(out.client_pn == 2);
}

/* v is one of p's listed supported versions. */
static int vneg_lists(const quic_vneg_packet* p, u32 v) {
  for (usz i = 0; i < p->count; i++)
    if (quic_get_be32(p->versions + 4 * i) == v) return 1;
  return 0;
}

/* An unknown-version long-header datagram of answerable size draws a Version
 * Negotiation packet with the connection ids swapped and this server's
 * supported versions -- v1 and v2 (RFC 9368 5) -- offered (RFC 9000 5.2.2 /
 * RFC 8999 6). */
static void test_srvboot_vneg_responds_to_alien_version(void) {
  u8               dg[1200] = {0};
  u8               vn[64];
  usz              n;
  quic_vneg_packet p;
  dg[0] = 0xd3; /* long header, some alien version's type bits */
  dg[1] = 0x0a;
  dg[2] = 0x0a;
  dg[3] = 0x0a;
  dg[4] = 0x0a; /* GREASE-shaped version, never supported (RFC 8999 6) */
  dg[5] = 8;    /* DCID */
  for (usz i = 0; i < 8; i++) dg[6 + i] = (u8)(0x11 * (i + 1));
  dg[14] = 5; /* SCID */
  for (usz i = 0; i < 5; i++) dg[15 + i] = (u8)(0xa0 + i);
  n = wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn);
  CHECK(n > 0);
  CHECK(quic_vneg_parse(vn, n, &p) == n);
  CHECK(p.dcid_len == 5); /* response DCID = received SCID */
  CHECK(p.dcid[0] == 0xa0 && p.dcid[4] == 0xa4);
  CHECK(p.scid_len == 8); /* response SCID = received DCID */
  CHECK(p.scid[0] == 0x11 && p.scid[7] == 0x88);
  CHECK(p.count == 2);
  CHECK(vneg_lists(&p, 1));
  CHECK(vneg_lists(&p, QUIC_VERSION_2));
}

/* A QUIC v2 Initial (RFC 9369) is a version this server now speaks
 * directly -- it must NOT draw a Version Negotiation packet (RFC 9368 2: no
 * VN round trip for an already-supported compatible version). */
static void test_srvboot_vneg_not_owed_for_v2(void) {
  u8 dg[1200] = {0};
  dg[0]       = 0xd3; /* long header, v2 Initial type bits 01 */
  dg[1]       = 0x6b;
  dg[2]       = 0x33;
  dg[3]       = 0x43;
  dg[4]       = 0xcf; /* QUIC v2 version number */
  dg[5]       = 8;
  for (usz i = 0; i < 8; i++) dg[6 + i] = (u8)(0x11 * (i + 1));
  dg[14] = 5;
  for (usz i = 0; i < 5; i++) dg[15 + i] = (u8)(0xa0 + i);
  u8 vn[64];
  CHECK(wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn) == 0);
}

/* No Version Negotiation for: an under-1200 datagram (amplification guard),
 * version 0 (never answer VN with VN, RFC 9000 6.1), version 1 (supported),
 * a short header, or an unparseable header. */
static void test_srvboot_vneg_guards(void) {
  u8 dg[1200] = {0};
  u8 vn[64];
  dg[0]  = 0xd3;
  dg[4]  = 0xcf; /* alien version 0x000000cf */
  dg[5]  = 4;
  dg[10] = 4;
  CHECK(wired_srvboot_vneg(quic_span_of(dg, 1199), vn, sizeof vn) == 0);
  CHECK(wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn) > 0);
  dg[4] = 0; /* version 0: a VN packet itself */
  CHECK(wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn) == 0);
  dg[4] = 1; /* version 1: supported, normal path */
  CHECK(wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn) == 0);
  dg[4] = 0xcf;
  dg[0] = 0x53; /* short header */
  CHECK(wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn) == 0);
  dg[0] = 0xd3;
  dg[5] = 21; /* DCID longer than any valid connection id */
  CHECK(wired_srvboot_vneg(quic_span_of(dg, sizeof dg), vn, sizeof vn) == 0);
}

/* Build the fixed test client's raw ClientHello bytes (no CRYPTO framing). */
static usz sb_build_raw_ch(quic_client* c, u8* ch, usz cap) {
  usz n;
  u8  cpriv[32], cpub[32];
  for (usz i = 0; i < 32; i++) cpriv[i] = (u8)(7 + i);
  quic_x25519_base(cpub, cpriv);
  quic_tlsdriver_init(&c->tls, cpriv, cpub, 0);
  n = quic_tlsdriver_raw_client_hello(&c->tls, ch, cap);
  CHECK(n > 100); /* both split chunks below must be non-empty */
  return n;
}

/* Seal one ClientHello chunk as its own protected Initial datagram at the
 * given CRYPTO offset and packet number — the shape each piece of an
 * oversized (split) ClientHello arrives in. */
static usz sb_seal_ch_chunk(u8* dg, usz cap, quic_span chunk, u64 off, u64 pn) {
  quic_initpkt_desc d = {
      quic_span_of(g_scid, 6), quic_span_of(g_scid, 6), chunk, pn, off};
  quic_obuf o = quic_obuf_of(dg, cap);
  CHECK(quic_initpkt_build(&d, &o) == 1);
  return o.len;
}

/* Accept from the accumulator with the fixed identity; returns the result. */
static int sb_accept_acc(wired_srvboot_acc* a, wired_srvboot_out* out) {
  wired_server       s;
  wired_srvloop      l;
  wired_srvboot_id   id;
  u8                 priv[32], pub[32], seed[32], rnd[32];
  wired_srvboot_conn conn = {&s, &l};
  sb_make_id(&id, priv, pub, seed, rnd);
  return wired_srvboot_accept_acc(&conn, &id, a, out);
}

/* A ClientHello split across two Initial datagrams is incomplete after the
 * first (no flight may be sent yet) and accepted after the second, ACKing
 * the highest packet number received (RFC 9000 19.6 / 13.2.1). */
static void test_bootacc_split_two_datagrams(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], dg2[1400], ini[1500], hs[1500];
  quic_obuf         iob = {ini, sizeof ini, 0};
  quic_obuf         hob = {hs, sizeof hs, 0};
  wired_srvboot_out out = {&iob, &hob, {0}, 0, 0};
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz n2 =
      sb_seal_ch_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 1);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 0);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg2, n2)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 1);
  CHECK(sb_accept_acc(&a, &out) == 1);
  CHECK(out.client_pn == 1);
  CHECK(iob.len >= 1200);
}

/* RFC 9000 17.2.3: build a minimal 0-RTT long-header datagram's leading
 * bytes (byte0 | version | zero-length DCID | zero-length SCID | ...) -- the
 * accumulator only inspects byte0+version to route a datagram to the 0-RTT
 * buffer (wired_srvboot_acc_feed), so the rest of the bytes are an arbitrary
 * fingerprint the test checks comes back unchanged. */
static usz sb_build_zerortt_dg(u8* dg, usz cap, u8 fingerprint) {
  usz n = 0;
  CHECK(cap >= 8);
  dg[n++] = 0xd1; /* long | fixed | type 0-RTT (01) | pn_len-1 = 0 */
  dg[n++] = 0;
  dg[n++] = 0;
  dg[n++] = 0;
  dg[n++] = 1; /* version 1 */
  dg[n++] = 0; /* DCID len 0 */
  dg[n++] = 0; /* SCID len 0 */
  dg[n++] = fingerprint;
  return n;
}

/* RFC 9001 4.6.1: a 0-RTT datagram arriving before this boot's Initial
 * keys/ClientHello even exist is buffered rather than refused, and comes
 * back out verbatim once the boot needs to replay it. */
static void test_bootacc_zerortt_buffered_verbatim(void) {
  u8                dg0[8], dg1[8];
  usz               n0, n1;
  wired_srvboot_acc a;
  n0 = sb_build_zerortt_dg(dg0, sizeof dg0, 0xaa);
  n1 = sb_build_zerortt_dg(dg1, sizeof dg1, 0xbb);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_zerortt_count(&a) == 0);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg0, n0)) == 1);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(wired_srvboot_acc_zerortt_count(&a) == 2);
  {
    quic_span t0 = wired_srvboot_acc_zerortt_take(&a, 0);
    quic_span t1 = wired_srvboot_acc_zerortt_take(&a, 1);
    CHECK(t0.n == n0 && t0.p[7] == 0xaa);
    CHECK(t1.n == n1 && t1.p[7] == 0xbb);
  }
  /* An unreassembled 0-RTT-only accumulator never reports a complete
   * ClientHello -- 0-RTT datagrams do not feed the CRYPTO reassembly. */
  CHECK(wired_srvboot_acc_complete(&a) == 0);
  /* Out of range yields an empty span rather than reading past zerortt_n. */
  CHECK(wired_srvboot_acc_zerortt_take(&a, 2).n == 0);
}

/* wired_srvboot_acc_reset (spent after a successful boot, or a fresh
 * connection attempt claiming a reused slot) empties the 0-RTT buffer too --
 * otherwise a stale datagram from a prior attempt on this slot would be
 * replayed into the new connection. */
static void test_bootacc_zerortt_cleared_on_reset(void) {
  u8                dg0[8];
  usz               n0 = sb_build_zerortt_dg(dg0, sizeof dg0, 0xcc);
  wired_srvboot_acc a;
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg0, n0)) == 1);
  CHECK(wired_srvboot_acc_zerortt_count(&a) == 1);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_zerortt_count(&a) == 0);
}

/* A 0-RTT datagram interleaved with the Initial datagrams a ClientHello is
 * reassembled from does not disturb that reassembly -- 0-RTT and Initial
 * absorption are independent (RFC 9000 12.2/RFC 9001 4.6.1: 0-RTT may
 * legitimately arrive ahead of, behind, or between Initial pieces). */
static void test_bootacc_zerortt_interleaved_with_initial(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], dg2[1400], dgz[8];
  usz               nz;
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz n2 =
      sb_seal_ch_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 1);
  nz = sb_build_zerortt_dg(dgz, sizeof dgz, 0xee);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dgz, nz)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 0);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg2, n2)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 1);
  CHECK(wired_srvboot_acc_zerortt_count(&a) == 1);
  CHECK(wired_srvboot_acc_zerortt_take(&a, 0).p[7] == 0xee);
}

/* Chunks arriving in reverse order still complete the ClientHello: each is
 * buffered at its offset and only the contiguous prefix decides. */
static void test_bootacc_out_of_order(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], dg2[1400];
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz n2 =
      sb_seal_ch_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 1);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg2, n2)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 0);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 1);
}

/* A datagram whose DCID differs from the one that claimed the accumulator
 * is refused outright: buffer, contiguity, and packet-number state stay
 * untouched (its Initial keys belong to another connection). */
static void test_bootacc_foreign_dcid_ignored(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], alien[1400];
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz na;
  {
    static const u8   other[6] = {9, 9, 9, 9, 9, 9};
    quic_initpkt_desc d        = {
        quic_span_of(other, 6), quic_span_of(g_scid, 6),
        quic_span_of(ch + 60, n - 60), 5, 60};
    quic_obuf o = quic_obuf_of(alien, sizeof alien);
    CHECK(quic_initpkt_build(&d, &o) == 1);
    na = o.len;
  }
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  {
    usz before = a.cr.received_to;
    u64 pn     = a.largest_pn;
    CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(alien, na)) == 0);
    CHECK(a.cr.received_to == before);
    CHECK(a.largest_pn == pn);
    CHECK(wired_srvboot_acc_complete(&a) == 0);
  }
}

/* Retransmitted (duplicate) chunks are idempotent: feeding the same
 * datagram twice leaves the buffer exactly as one feed did. */
static void test_bootacc_duplicate_idempotent(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], dg2[1400];
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz n2 =
      sb_seal_ch_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 1);
  u8 copy[1400];
  for (usz i = 0; i < n1; i++) copy[i] = dg1[i];
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(copy, n1)) == 1);
  CHECK(a.cr.received_to == 60);
  CHECK(wired_srvboot_acc_complete(&a) == 0);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg2, n2)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 1);
}

/* The recorded largest packet number never regresses, and the accepted
 * flight ACKs that maximum — not whichever packet happened to arrive last
 * (RFC 9000 13.2.1). */
static void test_bootacc_pn_monotone_ack_max(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], dg2[1400], ini[1500], hs[1500];
  quic_obuf         iob = {ini, sizeof ini, 0};
  quic_obuf         hob = {hs, sizeof hs, 0};
  wired_srvboot_out out = {&iob, &hob, {0}, 0, 0};
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 1);
  usz n2 =
      sb_seal_ch_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 2);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg2, n2)) == 1);
  CHECK(a.largest_pn == 2);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(a.largest_pn == 2);
  CHECK(sb_accept_acc(&a, &out) == 1);
  CHECK(out.client_pn == 2);
}

/* A CRYPTO chunk falling outside the reassembly buffer is dropped without
 * disturbing what was already buffered. */
static void test_bootacc_overflow_chunk_ignored(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], wild[1400];
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz               n1, nw;
  (void)n;
  n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  nw = sb_seal_ch_chunk(wild, sizeof wild, quic_span_of(ch, 60), 2040, 3);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  wired_srvboot_acc_feed(&a, quic_mspan_of(wild, nw));
  CHECK(a.cr.received_to == 60);
  CHECK(wired_srvboot_acc_complete(&a) == 0);
}

/* Two Initial packets coalesced into ONE datagram (RFC 9000 12.2) are both
 * opened and both chunks land — not just the first packet. */
static void test_bootacc_coalesced_initials(void) {
  quic_client       c;
  u8                ch[2048], dg[2900];
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg, sizeof dg, quic_span_of(ch, 60), 0, 0);
  usz n2 = sb_seal_ch_chunk(
      dg + n1, sizeof dg - n1, quic_span_of(ch + 60, n - 60), 60, 1);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg, n1 + n2)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 1);
  CHECK(a.largest_pn == 1);
}

/* PARTIAL-CLIENTHELLO ACK (RFC 9000 13.2.1): while the ClientHello is
 * still incomplete the server may not send its flight, but it must still
 * acknowledge the Initial packets it did open -- otherwise a client whose
 * missing half keeps getting dropped hears nothing at all and gives up on
 * its own 5s handshake idle timer (observed live under the interop
 * runner's 30% bursty loss). The ack's own pn starts at 2 and climbs, so
 * it never collides with the accept flight's server Initial pn 1. */
static void test_srvboot_partial_ack_builds_and_advances_pn(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], out[1400];
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 7);
  (void)n;
  usz an;
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 0);
  CHECK(a.ack_pn == 2);
  an = wired_srvboot_partial_ack(&a, quic_span_of(g_scid, 6), out, sizeof out);
  CHECK(an > 0);
  /* not ack-eliciting, so no 1200-byte floor (RFC 9000 14.1) -- and a
   * padded ack burned ~25x more RFC 9000 8.1 budget, starving the
   * amplificationlimit flight's withheld tail */
  CHECK(an < 200);
  CHECK(a.ack_pn == 3);
  CHECK(
      wired_srvboot_partial_ack(&a, quic_span_of(g_scid, 6), out, sizeof out) >
      0);
  CHECK(a.ack_pn == 4);
}

/* Nothing authenticated yet: no ack may be reflected (an unauthenticated
 * source address must not draw amplified traffic, RFC 9000 8.1). */
static void test_srvboot_partial_ack_needs_opened_packet(void) {
  wired_srvboot_acc a;
  u8                out[1400];
  wired_srvboot_acc_reset(&a);
  CHECK(
      wired_srvboot_partial_ack(&a, quic_span_of(g_scid, 6), out, sizeof out) ==
      0);
}

/* RFC 9000 7.2: the client switches its DCID to the server's scid upon the
 * first server packet -- after a partial ack that is the very next
 * datagram. wired_srvboot_acc_allow admits that new DCID into the bound
 * accumulator (keys stay the ODCID's); before the allow it is rejected as
 * foreign. */
static void test_srvboot_acc_allows_switched_dcid(void) {
  quic_client       c;
  u8                ch[2048], dg1[1400], dga[1400];
  u8                alt[6] = {9, 9, 9, 9, 9, 9};
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz n1 = sb_seal_ch_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  quic_initpkt_desc d = {
      quic_span_of(alt, 6), quic_span_of(alt, 6), quic_span_of(ch + 60, n - 60),
      1, 60};
  quic_obuf o = quic_obuf_of(dga, sizeof dga);
  CHECK(quic_initpkt_build(&d, &o) == 1);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg1, n1)) == 1);
  CHECK(srvboot_acc_admit(&a, quic_mspan_of(dga, o.len)) == 0);
  wired_srvboot_acc_allow(&a, quic_span_of(alt, 6));
  CHECK(srvboot_acc_admit(&a, quic_mspan_of(dga, o.len)) == 1);
}

/* An authenticated ClientHello the server cannot serve (its key_share
 * carries only a hybrid group, no standalone x25519) draws an Initial
 * CONNECTION_CLOSE with the TLS handshake_failure code, acknowledging the
 * received packet, so the peer fails fast instead of retrying into a
 * timeout (RFC 9001 4.8 / RFC 9000 10.2). */
static void test_srvboot_refusal_closes_unservable(void) {
  quic_client       c;
  u8                ch[512], dg[1400], ref[1500];
  u8                ini[1500], hs[1500];
  quic_obuf         iob = {ini, sizeof ini, 0};
  quic_obuf         hob = {hs, sizeof hs, 0};
  wired_srvboot_out out = {&iob, &hob, {0}, 0, 0};
  wired_srvboot_acc a;
  usz               n = sb_build_raw_ch(&c, ch, sizeof ch);
  usz               nd, nr, hit = 0;
  /* rewrite the x25519 key_share entry's group to a hybrid id the server
   * does not implement (entry header 001d 0020 -> 11ec 0020) */
  for (usz i = 0; i + 4 <= n; i++)
    if (ch[i] == 0 && ch[i + 1] == 0x1d && ch[i + 2] == 0 &&
        ch[i + 3] == 0x20) {
      ch[i]     = 0x11;
      ch[i + 1] = 0xec;
      hit       = 1;
      break;
    }
  CHECK(hit == 1);
  nd = sb_seal_ch_chunk(dg, sizeof dg, quic_span_of(ch, n), 0, 3);
  wired_srvboot_acc_reset(&a);
  CHECK(wired_srvboot_acc_feed(&a, quic_mspan_of(dg, nd)) == 1);
  CHECK(wired_srvboot_acc_complete(&a) == 1);
  CHECK(sb_accept_acc(&a, &out) == 0); /* unservable key share */
  nr = wired_srvboot_refusal(&a, quic_span_of(g_scid, 6), ref, sizeof ref);
  CHECK(nr >= 1200); /* a padded server Initial datagram */
  {
    quic_initial_keys ck, sk;
    quic_aes128       hp;
    quic_span         frames;
    quic_protect_keys k;
    quic_rx_desc      d = {quic_mspan_of(ref, nr), 1};
    quic_initpkt_derive(quic_span_of(g_scid, 6), &ck, &sk);
    quic_aes128_init(&hp, sk.hp);
    k = (quic_protect_keys){&sk, &hp};
    CHECK(quic_rx_packet(&k, &d, &frames) == 1);
    /* CONNECTION_CLOSE (transport): type 1c, code 0x128 (varint 41 28),
     * frame type 0, empty reason */
    CHECK(frames.p[0] == 0x1c);
    CHECK(frames.p[1] == 0x41 && frames.p[2] == 0x28);
    CHECK(frames.p[3] == 0x00 && frames.p[4] == 0x00);
  }
}

/* Identity whose Certificate carries the external realchain, leaf first, root
 * included (RFC 8446 4.4.2 allows it) so the flight outgrows one MTU datagram,
 * signing the CertificateVerify with the leaf's P-256 key. File-scope: sdrv
 * holds the chain as views for the connection's lifetime. */
static quic_span sb_chain[3];

static void sb_make_chain_id(
    wired_srvboot_id* id, u8 priv[32], u8 pub[32], u8 rnd[32]) {
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x40 + i);
    rnd[i]  = (u8)(0xa0 + i);
  }
  quic_x25519_base(pub, priv);
  sb_chain[0] =
      quic_span_of(quic_realchain_leaf_der, sizeof quic_realchain_leaf_der);
  sb_chain[1] =
      quic_span_of(quic_realchain_int_der, sizeof quic_realchain_int_der);
  sb_chain[2] =
      quic_span_of(quic_realchain_root_der, sizeof quic_realchain_root_der);
  id->priv                    = priv;
  id->pub                     = pub;
  id->cert_seed               = quic_realchain_leaf_priv;
  id->scid                    = g_scid;
  id->scid_len                = 6;
  id->random                  = rnd;
  id->chain                   = sb_chain;
  id->chain_count             = 3;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 0;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
  id->retry_odcid             = 0;
  id->retry_odcid_len         = 0;
  id->ticket_key              = 0;
}

/* A bootstrapped server with the realchain identity plus everything the
 * client side needs to finish the handshake from the sealed reply datagrams:
 * the client's ECDHE private, its raw ClientHello, and the reply buffers. */
struct sb_split_fix {
  quic_client       c;
  wired_server      s;
  wired_srvloop     l;
  u8                priv[32], pub[32], rnd[32];
  u8                cpriv[32];
  u8                ch[512];
  usz               ch_len;
  u8                ini[1500];
  u8                hs[4096];
  quic_obuf         iob, hob;
  wired_srvboot_out out;
};

/* Cold-start a server from a fresh protected client Initial, with the
 * realchain identity. The raw ClientHello is captured first: the wire builder
 * emits the identical bytes (zero random, same key_share), so the client can
 * reconstruct the transcript the server folded. */
static void sb_split_boot(struct sb_split_fix* f) {
  wired_srvboot_id   id;
  u8                 cpub[32], dg[1500];
  usz                total = 0;
  wired_srvboot_conn conn  = {&f->s, &f->l};
  wired_srvboot_in   in;
  f->iob = quic_obuf_of(f->ini, sizeof f->ini);
  f->hob = quic_obuf_of(f->hs, sizeof f->hs);
  f->out = (wired_srvboot_out){&f->iob, &f->hob, {0}, 0, 0};
  for (usz i = 0; i < 32; i++) f->cpriv[i] = (u8)(7 + i);
  quic_x25519_base(cpub, f->cpriv);
  quic_tlsdriver_init(&f->c.tls, f->cpriv, cpub, 0);
  f->ch_len = quic_tlsdriver_raw_client_hello(&f->c.tls, f->ch, sizeof f->ch);
  CHECK(f->ch_len > 0);
  {
    quic_clientwire_hdr_in hdr = {
        quic_span_of(g_scid, 6), quic_span_of(g_scid, 6), 0};
    quic_obuf ob = quic_obuf_of(dg, sizeof dg);
    CHECK(quic_client_build_initial_wire(&f->c, &hdr, &ob) == 1);
    total = ob.len;
  }
  sb_make_chain_id(&id, f->priv, f->pub, f->rnd);
  in = (wired_srvboot_in){&id, quic_mspan_of(dg, total)};
  CHECK(wired_srvboot_accept(&conn, &in, &f->out) == 1);
}

/* RFC 9000 19.6 / 14.1: a TLS flight too large for one MTU datagram is split
 * into multiple Handshake packet datagrams, each within 1500 bytes, whose
 * lengths partition the flight buffer; later Handshake sends continue after
 * the flight's packet numbers 0..dgram_count-1. */
static void test_srvboot_split_flight_datagrams(void) {
  static struct sb_split_fix f;
  usz                        sum = 0;
  sb_split_boot(&f);
  CHECK(f.out.dgram_count >= 2);
  CHECK(f.out.dgram_count <= WIRED_SRVBOOT_FLIGHT_MAX);
  for (usz i = 0; i < f.out.dgram_count; i++) {
    CHECK(f.out.dgram_len[i] > 0);
    CHECK(f.out.dgram_len[i] <= 1500);
    sum += f.out.dgram_len[i];
  }
  CHECK(sum == f.hob.len);
  CHECK(f.l.hs_tx_pn == f.out.dgram_count);
}

/* Open each flight datagram with SERVER_HS and collect its CRYPTO frames into
 * the reassembler, in forward or reverse datagram order. */
static void sb_split_collect(
    struct sb_split_fix* f, int reverse, quic_crecv* cr) {
  const quic_initial_keys* shs;
  quic_aes128              hp;
  usz                      offs[WIRED_SRVBOOT_FLIGHT_MAX], off = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_SERVER_HS, &shs) == 1);
  quic_aes128_init(&hp, shs->hp);
  quic_protect_keys pk = {shs, &hp};
  for (usz i = 0; i < f->out.dgram_count; i++) {
    offs[i] = off;
    off += f->out.dgram_len[i];
  }
  quic_crecv_init(cr);
  for (usz k = 0; k < f->out.dgram_count; k++) {
    usz       i = reverse ? f->out.dgram_count - 1 - k : k;
    quic_span frames;
    CHECK(
        quic_hspkt_open(
            &pk, quic_mspan_of(f->hs + offs[i], f->out.dgram_len[i]),
            &frames) == 1);
    CHECK(quic_crecv_collect(cr, frames.p, frames.n) == 1);
  }
}

/* Walk the reassembled EncryptedExtensions..CertificateVerify into the
 * transcript, then check the trailing server Finished against it
 * (RFC 8446 4.4.4). */
static void sb_split_check_finished(
    const quic_crecv* cr, quic_transcript* tr, const u8 s_traffic[32]) {
  const u8* fl;
  usz       fln, p = 0;
  u8        th[32];
  quic_crecv_message(cr, &fl, &fln);
  CHECK(fln > 0);
  while (p + 4 <= fln && fl[p] != QUIC_HS_FINISHED) {
    usz mlen = 4 + (((usz)fl[p + 1] << 16) | ((usz)fl[p + 2] << 8) | fl[p + 3]);
    CHECK(p + mlen <= fln);
    if (p + mlen > fln) return; /* garbled reassembly: already FAILed above */
    quic_transcript_add(tr, fl + p, mlen);
    p += mlen;
  }
  CHECK(p + 4 <= fln);
  if (p + 4 > fln) return; /* no Finished found: already FAILed above */
  quic_transcript_hash(tr, th);
  CHECK(quic_tls_finished_check(s_traffic, th, fl + p + 4) == 1);
}

/* Client side of a split flight: open the server Initial (ServerHello), open
 * each Handshake datagram in the given order, reassemble the CRYPTO stream by
 * offset (RFC 9000 19.6), and verify the server Finished over the reassembled
 * transcript with independently derived client-side secrets — the handshake
 * completes only if every chunk landed at its correct stream offset. */
static void sb_split_client_handshake(int reverse) {
  static struct sb_split_fix f;
  quic_serverhello_out       sho;
  quic_span                  shv;
  u8              sh_pub[32], shared[32], hsec[32], th[32], s_traffic[32];
  quic_transcript tr;
  quic_crecv      cr;
  sb_split_boot(&f);
  CHECK(f.out.dgram_count >= 2);
  {
    quic_clientwire_open_in oin = {
        quic_span_of(g_scid, 6), quic_mspan_of(f.ini, f.iob.len), 0};
    CHECK(quic_client_open_initial_wire(&oin, &shv) == 1);
  }
  CHECK(quic_tls_parse_server_hello(shv, sh_pub, &sho) == 1);
  quic_x25519(shared, f.cpriv, sh_pub);
  quic_tls_handshake_secret(shared, hsec);
  quic_transcript_init(&tr);
  quic_transcript_add(&tr, f.ch, f.ch_len);
  quic_transcript_add(&tr, shv.p, shv.n);
  quic_transcript_hash(&tr, th);
  {
    quic_hkdf_label shl = {"s hs traffic", 12, {th, 32}};
    quic_hkdf_expand_label(hsec, &shl, quic_mspan_of(s_traffic, 32));
  }
  sb_split_collect(&f, reverse, &cr);
  sb_split_check_finished(&cr, &tr, s_traffic);
}

/* In-order delivery reassembles and completes. */
static void test_srvboot_split_flight_reassembled(void) {
  sb_split_client_handshake(0);
}

/* Reversed delivery still reassembles by CRYPTO offset and completes. */
static void test_srvboot_split_flight_out_of_order(void) {
  sb_split_client_handshake(1);
}

void test_h3_loopback(void) {
  test_loopback_initial_datagram();
  test_loopback_wire_confirm_and_get();
  test_srvboot_accept();
  test_srvboot_reply_dcid_is_client_scid();
  test_srvboot_reply_dcid_empty_client_scid();
  test_srvboot_rejects_non_initial();
  test_srvboot_acks_actual_initial_pn();
  test_srvboot_vneg_responds_to_alien_version();
  test_srvboot_vneg_not_owed_for_v2();
  test_srvboot_vneg_guards();
  test_bootacc_split_two_datagrams();
  test_bootacc_zerortt_buffered_verbatim();
  test_bootacc_zerortt_cleared_on_reset();
  test_bootacc_zerortt_interleaved_with_initial();
  test_bootacc_out_of_order();
  test_bootacc_foreign_dcid_ignored();
  test_bootacc_duplicate_idempotent();
  test_bootacc_pn_monotone_ack_max();
  test_bootacc_overflow_chunk_ignored();
  test_bootacc_coalesced_initials();
  test_srvboot_partial_ack_builds_and_advances_pn();
  test_srvboot_partial_ack_needs_opened_packet();
  test_srvboot_acc_allows_switched_dcid();
  test_srvboot_refusal_closes_unservable();
  test_srvboot_split_flight_datagrams();
  test_srvboot_split_flight_reassembled();
  test_srvboot_split_flight_out_of_order();
}
