#include "app/http3/server/srvloop/srvloop.h"

#include "app/datagram/datagram/datagram.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvwire/wire.h"
#include "crypto/kdf/keys/keyset.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/newsessionticket.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "tls/keys/ticket/ticket.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/frame/frame/ack.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/framewalk.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9001 4 / 5 / 5.1, RFC 9000 17.2: the server real-wire loop. The server
 * seals with its own direction (SERVER_*) and opens with the peer direction
 * (CLIENT_*). The client role is simulated symmetrically using the same keys
 * the server's schedule holds, so seal-then-open across the wire is identity.
 * A normal exchange climbs Initial -> Handshake -> 1-RTT; a forged Finished
 * promotes nothing; the wrong direction key fails to open. */

static const u8 g_cli_scid[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* View a loop's stream-0 cross-datagram request accumulator (RFC 9000 2.2), so
 * a direct wired_srvloop_dispatch call reassembles into the loop's own buffer.
 * These tests all drive the request stream (id 0), so slot 0 is the one the
 * table would allocate for it (wired_srvloop_step's stream_slot_for does the
 * same lookup on the live path). */
static wired_srvloop_reqacc lp_reqacc(wired_srvloop* l) {
  wired_srvloop_reqacc       acc;
  wired_srvloop_stream_slot* slot = &l->streams[0];
  acc.buf                         = slot->req_buf;
  acc.cap                         = sizeof slot->req_buf;
  acc.len                         = &slot->req_len;
  acc.fin                         = &slot->req_fin;
  acc.done                        = &slot->req_done;
  return acc;
}

/* View slot 0's re-wrap buffer (RFC 9000 2.2), the caller-owned storage a
 * direct wired_srvloop_dispatch call needs for in->wrap. */
static quic_mspan lp_wrap0(wired_srvloop* l) {
  return quic_mspan_of(l->streams[0].req_wrap, sizeof l->streams[0].req_wrap);
}

struct lp_fix {
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

static void lp_make_client_hello(struct lp_fix* f) {
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
static void lp_drive_to_flight(struct lp_fix* f) {
  u8 srv_priv[32], srv_pub[32], cert_seed[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  wired_server_init_in sin   = {srv_priv, srv_pub, cert_seed, 0, 0};
  quic_obuf            sh_ob = quic_obuf_of(f->sh, sizeof(f->sh));
  quic_obuf            fl_ob = quic_obuf_of(f->flight, sizeof(f->flight));
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  wired_server_init(&f->s, &sin);
  CHECK(
      wired_server_set_cids(
          &f->s, quic_span_of(g_cli_scid, 6), quic_span_of(g_cli_scid, 6)) ==
      1);
  CHECK(wired_srvloop_init(&f->l, g_cli_scid, 6) == 1);
  CHECK(wired_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
  CHECK(wired_server_build_flight(&f->s, f->srv_random, &fo) == 1);
  f->sh_len     = sh_ob.len;
  f->flight_len = fl_ob.len;
  CHECK(f->s.phase == WIRED_SERVER_HS_FLIGHT_SENT);
}

/* Compute the genuine client Finished message (RFC 8446 4.4.4). */
static void lp_make_client_finished(struct lp_fix* f) {
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

/* Client role: seal a Handshake CRYPTO flight toward the server with the
 * peer-direction CLIENT_HS key (which the server opens with). */
static usz client_seal_handshake(
    struct lp_fix* f, const u8* msg, usz mlen, u8* pkt, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  quic_obuf                ob = {pkt, cap, 0};
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_srvwire_seal_in in = {
      quic_span_of(f->s.sdrv.iscid, f->s.sdrv.iscid_len),
      quic_span_of(g_cli_scid, 6),
      0,
      -1,
      quic_span_of(msg, mlen),
      0};
  quic_protect_keys pk = {k, &hp};
  CHECK(quic_srvwire_seal_handshake(&pk, &in, &ob));
  return ob.len;
}

/* Client role: seal a Handshake packet at an explicit packet number. curl does
 * not send its Finished at PN 0 — it leads with an ACK-only Handshake packet,
 * so the Finished lands at a later PN. */
static usz client_seal_handshake_pn(
    struct lp_fix* f, u64 pn, const u8* msg, usz mlen, u8* pkt, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  quic_obuf                ob = {pkt, cap, 0};
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_srvwire_seal_in in = {
      quic_span_of(f->s.sdrv.iscid, f->s.sdrv.iscid_len),
      quic_span_of(g_cli_scid, 6),
      pn,
      -1,
      quic_span_of(msg, mlen),
      0};
  quic_protect_keys pk = {k, &hp};
  CHECK(quic_srvwire_seal_handshake(&pk, &in, &ob));
  return ob.len;
}

/* Client role: seal a 1-RTT STREAM payload toward the server with CLIENT_AP. */
static usz client_seal_onertt(
    struct lp_fix* f, const u8* pl, usz pln, u8* pkt, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_AP, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys      pk = {k, &hp};
  quic_hspkt_onertt_desc d  = {
      quic_span_of(f->s.sdrv.iscid, f->s.sdrv.iscid_len), 0,
      quic_span_of(pl, pln)};
  quic_obuf o = quic_obuf_of(pkt, cap);
  CHECK(quic_hspkt_onertt_build(&pk, &d, &o));
  total = o.len;
  return total;
}

/* DIRECTION: server seals Initial/Handshake and the matching open recovers the
 * bytes; the wrong-direction key fails. */
static void test_srvloop_send_initial_roundtrip(void) {
  struct lp_fix f;
  u8            pkt[1300];
  quic_obuf     ob  = {pkt, sizeof pkt, 0};
  quic_span     tls = {0, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  wired_srvloop_send_in in = {
      quic_span_of(g_cli_scid, 6), 1, -1, quic_span_of(f.sh, f.sh_len), 0};
  CHECK(wired_srvloop_send_initial(&f.s, &in, &ob));
  /* RFC 9000 14.1: the Initial datagram is padded to >= 1200, else curl drops
   * it and PTO-retransmits its own Initial for ~4s (the appconnect stall). */
  CHECK(ob.len >= 1200);
  {
    quic_srvwire_open_initial_in oin = {
        quic_span_of(f.s.sdrv.odcid, f.s.sdrv.odcid_len), 1};
    CHECK(quic_srvwire_open_initial(&oin, quic_mspan_of(pkt, ob.len), &tls));
  }
  CHECK(tls.n == f.sh_len); /* PADDING after CRYPTO is ignored on open */
}

/* DIRECTION SAFETY: a server-sealed Handshake packet (SERVER_HS) opens with the
 * server's own-direction key (the client's peer key) but NOT with CLIENT_HS,
 * the peer-direction key the server itself uses to open inbound packets. */
static void test_srvloop_wrong_direction_open_fails(void) {
  struct lp_fix            f;
  u8                       pkt[2300];
  quic_obuf                ob = {pkt, sizeof pkt, 0};
  const quic_initial_keys *own, *peer;
  quic_aes128              ownhp, peerhp;
  quic_span                tls = {0, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  quic_srvwire_seal_in in = {
      quic_span_of(g_cli_scid, 6),
      quic_span_of(g_cli_scid, 0),
      0,
      -1,
      quic_span_of(f.flight, f.flight_len),
      0};
  CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_HS, &own) == 1);
  quic_aes128_init(&ownhp, own->hp);
  {
    wired_srvloop_send_in sin = {
        quic_span_of(g_cli_scid, 6), 0, -1,
        quic_span_of(f.flight, f.flight_len), 0};
    CHECK(wired_srvloop_send_handshake(&f.s, &sin, &ob));
  }
  (void)in;
  /* SERVER_HS (own / client-peer) opens it; CLIENT_HS (server-open) must NOT.
   */
  {
    quic_protect_keys ownpk = {own, &ownhp};
    CHECK(
        quic_srvwire_open_handshake(&ownpk, quic_mspan_of(pkt, ob.len), &tls) ==
        1);
  }
  CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_CLIENT_HS, &peer) == 1);
  quic_aes128_init(&peerhp, peer->hp);
  {
    quic_protect_keys peerpk = {peer, &peerhp};
    CHECK(
        quic_srvwire_open_handshake(
            &peerpk, quic_mspan_of(pkt, ob.len), &tls) == 0);
  }
}

/* No 1-RTT key before confirmation: seal at 1-RTT is refused (RFC 9001 5). */
static void test_srvloop_no_onertt_seal_before_confirm(void) {
  struct lp_fix f;
  u8            pkt[256], frame[1] = {0x1e};
  quic_obuf     ob = {pkt, sizeof pkt, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  CHECK(wired_server_is_confirmed(&f.s) == 0);
  {
    wired_srvloop_send_in in = {
        quic_span_of(g_cli_scid, 6), 0, -1, quic_span_of(frame, 1), 0};
    CHECK(wired_srvloop_send_onertt(&f.s, &in, &ob) == 0);
  }
}

/* CENTRAL SAFETY: a forged client Finished does not promote the server, so the
 * step produces no HANDSHAKE_DONE and 1-RTT stays unarmed. */
static void test_srvloop_forged_finished_no_promote(void) {
  struct lp_fix f;
  u8            cpkt[512], out[512];
  usz           clen;
  quic_obuf     ob = {out, sizeof out, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  f.cli_fin[4] ^= 0x01;
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(cpkt, clen), &ob) ==
      0);
  CHECK(wired_server_is_confirmed(&f.s) == 0);
  {
    const quic_initial_keys* k;
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
  }
}

/* Client role: open a server-sealed 1-RTT packet with the peer SERVER_AP key
 * (the client's view) and view its raw frame payload. */
static int client_open_onertt(
    struct lp_fix* f, u8* pkt, usz len, const u8** pl, usz* pll) {
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

/* The confirmation 1-RTT payload carries a STREAM frame on the server control
 * stream (id 3) whose data leads with the control type 0x00 + SETTINGS, and
 * then a HANDSHAKE_DONE (0x1e) frame (RFC 9114 6.2.1 / RFC 9000 19.20). */
static void check_settings_and_done(const u8* pl, usz pll) {
  quic_stream_frame sf;
  usz               n = quic_frame_get_stream(pl, pll, &sf);
  CHECK(n > 0);
  CHECK(sf.stream_id == 3); /* first server unidirectional stream */
  CHECK(sf.length > 0 && sf.data[0] == 0x00); /* control stream type */
  CHECK(pll > n && pl[pll - 1] == 0x1e);      /* trailing HANDSHAKE_DONE */
}

/* LIVENESS: a genuine client Finished drives the server to confirmed. The step
 * now seals a coalesced datagram: a Handshake ACK of the client Finished
 * (RFC 9000 13.2.1) ahead of a 1-RTT packet carrying SETTINGS + HANDSHAKE_DONE
 * (RFC 9114 6.2.1). A following GET yields a decodable 200 (RFC 9114 4.1). */
static void test_srvloop_full_roundtrip(void) {
  struct lp_fix f;
  u8            cpkt[1024], out[1024], get[512];
  usz           clen, glen;
  quic_obuf     ob = {out, sizeof out, 0};
  const u8*     pkts[4];
  usz           offs[4], lens[4], np;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(cpkt, clen), &ob) ==
      1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  /* The reply coalesces a Handshake ACK (long header) and a 1-RTT packet. */
  quic_pktlist plist = {pkts, offs, lens, 4};
  np                 = quic_udploop_split(quic_span_of(out, ob.len), &plist);
  CHECK(np == 2);
  CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
  {
    const u8* pl;
    usz       pll;
    CHECK(client_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
    check_settings_and_done(pl, pll);
  }

  /* GET over 1-RTT -> a 200 response that the client can decode. */
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  {
    u8        spkt[1024];
    usz       slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
    const u8* pl;
    usz       pll;
    quic_h3conn_resp resp_out = {0};
    ob                        = (quic_obuf){out, sizeof out, 0};
    CHECK(
        wired_srvloop_step(
            &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen),
            &ob) == 1);
    CHECK(client_open_onertt(&f, out, ob.len, &pl, &pll) == 1);
    CHECK(quic_h3conn_recv_response(quic_span_of(pl, pll), &resp_out) == 1);
    CHECK(resp_out.status == 200);
  }
}

/* RFC 9000 17.3: the DCID of a short-header packet is out[1 .. 1+len], in the
 * clear (header protection masks only byte0 and the packet number). */
static int onertt_dcid_is(const u8* pkt, const u8* cid, u8 len) {
  for (u8 i = 0; i < len; i++)
    if (pkt[1 + i] != cid[i]) return 0;
  return 1;
}

/* RESPONSE DCID = CLIENT SCID (#28, RFC 9000 5.1 / 17.2): the server writes the
 * client's SCID — NOT the client's DCID — as the DCID of every reply, so a peer
 * that checks the reply DCID against its own SCID (curl does) accepts it. The
 * loop is seeded with a SCID distinct from g_cli_scid (the client DCID
 * stand-in) to prove the reply carries the SCID, not the DCID. */
static void test_srvloop_response_dcid_is_client_scid(void) {
  static const u8 cli_scid[6] = {'S', 'C', 'I', 'D', '0', '1'};
  struct lp_fix   f;
  u8              cpkt[1024], out[1024];
  usz             clen;
  quic_obuf       ob = {out, sizeof out, 0};
  const u8*       pkts[4];
  usz             offs[4], lens[4], np;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  /* re-seed the loop with the client's SCID (distinct from g_cli_scid). */
  CHECK(wired_srvloop_init(&f.l, cli_scid, 6) == 1);
  lp_make_client_finished(&f);
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(cpkt, clen), &ob) ==
      1);
  quic_pktlist plist = {pkts, offs, lens, 4};
  np                 = quic_udploop_split(quic_span_of(out, ob.len), &plist);
  CHECK(np == 2);                                    /* Handshake ACK + 1-RTT */
  CHECK(onertt_dcid_is(out + offs[1], cli_scid, 6)); /* DCID == client SCID */
  CHECK(
      !onertt_dcid_is(out + offs[1], g_cli_scid, 6)); /* NOT the client DCID */
}

/* Client role: seal a 1-RTT STREAM payload at an explicit packet number. */
static usz client_seal_onertt_pn(
    struct lp_fix* f, u64 pn, const u8* pl, usz pln, u8* pkt, usz cap) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_AP, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys      pk = {k, &hp};
  quic_hspkt_onertt_desc d  = {
      quic_span_of(f->s.sdrv.iscid, f->s.sdrv.iscid_len), pn,
      quic_span_of(pl, pln)};
  quic_obuf o = quic_obuf_of(pkt, cap);
  CHECK(quic_hspkt_onertt_build(&pk, &d, &o));
  total = o.len;
  return total;
}

/* Walk a 1-RTT payload and assert it carries an ACK frame whose largest range
 * acknowledges pn (RFC 9000 19.3) — this is what stops the client
 * retransmitting. */
static void check_acks_pn(const u8* pl, usz pll, u64 pn) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 found = 0;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr))
    if (fr.type == QUIC_FRAME_ACK) {
      quic_ack_frame a;
      CHECK(quic_ack_decode(fr.start, fr.remaining, &a) > 0);
      CHECK(a.ranges[0].hi == pn);
      found = 1;
    }
  CHECK(found);
}

/* Drive the loop to confirmed with a genuine client Finished. */
static void lp_confirm(struct lp_fix* f, quic_obuf* ob) {
  u8  cpkt[1024];
  usz clen;
  lp_make_client_hello(f);
  lp_drive_to_flight(f);
  lp_make_client_finished(f);
  clen =
      client_seal_handshake(f, f->cli_fin, f->cli_fin_len, cpkt, sizeof cpkt);
  ob->len = 0;
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f->l, &f->s}, quic_mspan_of(cpkt, clen), ob) ==
      1);
  CHECK(wired_server_is_confirmed(&f->s) == 1);
}

/* (C) ACK A 1-RTT GET: a decoded GET yields a 200 whose 1-RTT packet also
 * carries an ACK of the received GET's packet number (RFC 9000 13.2.1), so the
 * client stops retransmitting the GET once the 200 is received. */
static void test_srvloop_onertt_get_is_acked(void) {
  struct lp_fix f;
  u8            out[1024], get[512], spkt[1024];
  usz           glen, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  const u8*     pl;
  usz           pll;
  lp_confirm(&f, &ob);
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  slen = client_seal_onertt_pn(&f, 7, get, glen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob) ==
      1);
  CHECK(client_open_onertt(&f, out, ob.len, &pl, &pll) == 1);
  check_acks_pn(pl, pll, 7);
}

/* Open a server-sealed Handshake packet with the client's peer key (SERVER_HS)
 * and return its raw decrypted frame payload (quic_hspkt_open, not srvwire's
 * CRYPTO extractor — the ACK-only flight carries no CRYPTO frame). */
static int client_open_handshake(
    struct lp_fix* f, const u8* pkt, usz len, const u8** pl, usz* pll) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_SERVER_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys pk = {k, &hp};
  quic_span         v;
  if (!quic_hspkt_open(&pk, quic_mspan_of((u8*)pkt, len), &v)) return 0;
  *pl  = v.p;
  *pll = v.n;
  return 1;
}

/* REGRESSION (appconnect stall): a client Finished at a non-zero Handshake PN
 * must be acknowledged at that PN. The server previously ACKed a fixed PN 0, so
 * a Finished at any other PN went unacknowledged and the client PTO-
 * retransmitted it for ~4s (RFC 9000 13.2.1). */
static void test_srvloop_handshake_ack_tracks_pn(void) {
  struct lp_fix f;
  u8            cpkt[1024], out[1024];
  usz           clen;
  quic_obuf     ob = {out, sizeof out, 0};
  const u8 *    pkts[4], *pl;
  usz           offs[4], lens[4], np, pll;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  clen = client_seal_handshake_pn(
      &f, 3, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(cpkt, clen), &ob) ==
      1);
  quic_pktlist plist = {pkts, offs, lens, 4};
  np                 = quic_udploop_split(quic_span_of(out, ob.len), &plist);
  CHECK(np == 2);
  CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
  CHECK(client_open_handshake(&f, out + offs[0], lens[0], &pl, &pll) == 1);
  check_acks_pn(pl, pll, 3); /* ACKs the Finished's PN 3, not the fixed 0 */
}

/* Walk a 1-RTT payload and assert it carries all three: the control-stream
 * SETTINGS (id 3), a HANDSHAKE_DONE (0x1e), and a decodable 200 on the request
 * stream (id 0) — regardless of frame order (RFC 9114 6.2.1 / 4.1, RFC 9000
 * 19.20). The 200's STREAM frame (type byte onward) is fed to recv_response. */
static void check_confirm_and_200_payload(const u8* pl, usz pll) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 settings = 0, done = 0, ok200 = 0;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr)) {
    u64               type  = fr.type;
    const u8*         frame = fr.start;
    usz               rem   = fr.remaining;
    quic_stream_frame sf;
    quic_h3conn_resp  resp_out = {0};
    if (type == 0x1e) done = 1;
    if (type < 0x08 || type > 0x0f || !quic_frame_get_stream(frame, rem, &sf))
      continue;
    if (sf.stream_id == 3) settings = 1;
    if (sf.stream_id == 0 &&
        quic_h3conn_recv_response(quic_span_of(frame, rem), &resp_out) &&
        resp_out.status == 200)
      ok200 = 1;
  }
  CHECK(settings && done && ok200);
}

/* Confirm the server by dispatching its Finished directly (deriving the 1-RTT
 * keys) WITHOUT running produce, so the confirmation has not yet been sealed:
 * s->hs_done_sent and the loop latches stay 0. This sets up the same internal
 * state curl reaches when it coalesces its Finished and GET in one datagram. */
static void lp_confirm_via_dispatch(struct lp_fix* f) {
  u8                   scratch[512];
  wired_h3reqdrive_req req;
  int                  got = 0;
  quic_crypto_frame    cf;
  u8                   payload[256];
  usz                  plen;
  lp_make_client_hello(f);
  lp_drive_to_flight(f);
  lp_make_client_finished(f);
  cf.offset = 0;
  cf.length = f->cli_fin_len;
  cf.data   = f->cli_fin;
  plen      = quic_frame_put_crypto(payload, sizeof payload, &cf);
  {
    wired_srvloop_reqacc      acc = lp_reqacc(&f->l);
    wired_srvloop_dispatch_in in  = {
        quic_span_of(payload, plen), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f->l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f->s, &f->l.h3, &acc, 0}, &in) == 1);
  }
  CHECK(wired_server_is_confirmed(&f->s) == 1);
}

/* COALESCED CONFIRM + 200 (RFC 9000 12.2, RFC 9114 6.2.1): when one datagram
 * both confirms the handshake AND carries a GET, the reply coalesces the
 * confirmation (1-RTT SETTINGS + HANDSHAKE_DONE) with the 1-RTT 200 — so curl
 * receives SETTINGS to establish HTTP/3 and never gets the 200 alone with
 * SETTINGS still missing. */
static void test_srvloop_confirm_and_200_coalesce(void) {
  struct lp_fix f;
  u8            out[1500], get[512], spkt[1024];
  usz           glen, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  const u8*     pkts[4];
  usz           offs[4], lens[4], np;
  lp_confirm_via_dispatch(&f);
  CHECK(f.l.hs_done_sent == 0); /* confirmation not yet sealed */
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob) ==
      1);
  /* Reply: [Handshake ACK (long)][one 1-RTT packet: SETTINGS + HANDSHAKE_DONE
   * + 200]. Short-header packets carry no length, so confirm and 200 share a
   * single 1-RTT payload rather than two coalesced 1-RTT packets. */
  quic_pktlist plist = {pkts, offs, lens, 4};
  np                 = quic_udploop_split(quic_span_of(out, ob.len), &plist);
  CHECK(np == 2);
  CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
  {
    const u8* pl;
    usz       pll;
    CHECK(client_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
    check_confirm_and_200_payload(pl, pll); /* SETTINGS + DONE + 200 in one */
  }
}

/* (A) CONFIRM ONCE: after confirmation, a further 1-RTT datagram that does not
 * decode to a request must NOT re-emit the confirmation (SETTINGS +
 * HANDSHAKE_DONE). It either acks the received 1-RTT packet or sends nothing,
 * but never the confirmation again, so the client is not flooded with it. */
static void test_srvloop_confirm_emitted_once(void) {
  struct lp_fix f;
  u8  out[1024], junk[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  u8  spkt[1024];
  usz slen;
  quic_obuf ob = {out, sizeof out, 0};
  lp_confirm(&f, &ob);
  /* A 1-RTT packet that carries only PADDING: no request decoded. */
  slen = client_seal_onertt_pn(&f, 3, junk, sizeof junk, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  if (ob.len > 0) {
    const u8* pl;
    usz       pll;
    CHECK(client_open_onertt(&f, out, ob.len, &pl, &pll) == 1);
    /* must not be the confirmation: no HANDSHAKE_DONE trailer. */
    CHECK(!(pll > 0 && pl[pll - 1] == 0x1e));
  }
}

/* Prepend a PADDING (0x00) byte to src into dst; returns the new length. */
static usz lp_pad_prefix(u8* dst, const u8* src, usz n) {
  dst[0] = 0x00; /* RFC 9000 19.1 PADDING */
  for (usz i = 0; i < n; i++) dst[1 + i] = src[i];
  return n + 1;
}

/* Build a dispatcher payload [PADDING][CRYPTO(msg)] (RFC 9000 12.4 / 19.6). */
static usz lp_padding_then_crypto(u8* out, usz cap, const u8* msg, usz mlen) {
  quic_crypto_frame cf = {0, (u64)mlen, msg};
  out[0]               = 0x00; /* leading PADDING, as curl/quiche emit */
  return 1 + quic_frame_put_crypto(out + 1, cap - 1, &cf);
}

/* NON-CRYPTO-FIRST handshake: a Handshake payload that leads with PADDING
 * before its CRYPTO frame (curl/quiche do this) must still confirm. The
 * dispatcher is exercised directly because the wire helper wraps everything in
 * one CRYPTO frame (RFC 9000 12.4). */
static void test_srvloop_dispatch_padding_before_crypto(void) {
  struct lp_fix        f;
  u8                   payload[256];
  usz                  plen;
  wired_h3reqdrive_req req;
  u8                   scratch[512];
  int                  got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  plen =
      lp_padding_then_crypto(payload, sizeof payload, f.cli_fin, f.cli_fin_len);
  {
    wired_srvloop_reqacc      acc = lp_reqacc(&f.l);
    wired_srvloop_dispatch_in in  = {
        quic_span_of(payload, plen), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in) == 1);
  }
  CHECK(wired_server_is_confirmed(&f.s) == 1);
}

/* NON-STREAM-FIRST 1-RTT: a 1-RTT packet that leads with PADDING before the
 * STREAM frame still yields a 200 (RFC 9000 12.4). The full seal/open path is
 * used here since onertt carries the raw frame payload. */
static void test_srvloop_padding_before_stream(void) {
  struct lp_fix f;
  u8            cpkt[1024], out[1024], get[512], pget[576], spkt[1024];
  usz           clen, glen, plen, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(cpkt, clen), &ob) ==
      1);
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  plen = lp_pad_prefix(pget, get, glen);
  slen = client_seal_onertt(&f, pget, plen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob) ==
      1);
  CHECK(ob.len > 0);
}

/* COALESCED RECEIVE (RFC 9000 12.2): curl/quiche coalesce the client Finished
 * Handshake packet behind a leading packet (an Initial ACK or a PADDING-only
 * Handshake) in one datagram. A leading Handshake carrying only PADDING does
 * not confirm; the step must walk past it to the second slice's genuine
 * Finished and reach confirmed — proving the loop no longer drops non-first
 * slices. */
static void test_srvloop_coalesced_finished_behind_leading(void) {
  struct lp_fix f;
  u8            lead[256], rest[512], dg[1024], out[1024];
  u8            padding[1] = {0x00}; /* RFC 9000 19.1 */
  usz           lead_len, rest_len, i, off = 0;
  quic_obuf     ob = {out, sizeof out, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  lead_len = client_seal_handshake(&f, padding, 1, lead, sizeof lead);
  rest_len =
      client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, rest, sizeof rest);
  for (i = 0; i < lead_len; i++) dg[off++] = lead[i];
  for (i = 0; i < rest_len; i++) dg[off++] = rest[i];
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(dg, off), &ob) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
}

/* Build a STREAM frame on `stream_id` whose data is one type byte `lead`
 * (RFC 9114 6.2: control 0x00 / QPACK encoder 0x02 / decoder 0x03). */
static usz lp_uni_stream(u8* out, usz cap, u64 stream_id, u8 lead) {
  quic_stream_frame sf = {stream_id, 0, 1, &lead, 0};
  return quic_frame_put_stream(out, cap, &sf);
}

/* STREAM ID CLASSIFICATION (RFC 9000 2.1, RFC 9114 6.2): a 1-RTT payload that
 * carries only unidirectional STREAM frames (curl's control/encoder/decoder,
 * ids 2 and 6) must be accepted without being mistaken for a request — no
 * got_request, no error. */
static void test_srvloop_dispatch_uni_streams_not_request(void) {
  struct lp_fix        f;
  u8                   payload[256];
  usz                  off = 0;
  wired_h3reqdrive_req req;
  u8                   scratch[512];
  int                  got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
  off += lp_uni_stream(payload + off, sizeof payload - off, 6, 0x02);
  {
    wired_srvloop_reqacc      acc = lp_reqacc(&f.l);
    wired_srvloop_dispatch_in in  = {
        quic_span_of(payload, off), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in) == 1);
  }
  CHECK(got == 0);
}

/* A client bidi request stream (id 0, HEADERS=GET) arriving AFTER leading
 * unidirectional streams is the one decoded: the dispatcher skips the uni
 * STREAMs and drives the request (RFC 9000 2.1, RFC 9114 6.1/6.2). */
static void test_srvloop_dispatch_get_after_uni_streams(void) {
  struct lp_fix        f;
  u8                   payload[576], get[512];
  usz                  off = 0, glen;
  wired_h3reqdrive_req req;
  u8                   scratch[512];
  int                  got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
  off += lp_uni_stream(payload + off, sizeof payload - off, 3, 0x03);
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  for (usz i = 0; i < glen; i++) payload[off++] = get[i];
  {
    wired_srvloop_reqacc      acc = lp_reqacc(&f.l);
    wired_srvloop_dispatch_in in  = {
        quic_span_of(payload, off), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in) == 1);
  }
  CHECK(got == 1);
}

/* Build a POST as two separate request STREAM frames split at the HTTP/3
 * HEADERS/DATA boundary: hp = [STREAM off 0: HEADERS] (no FIN), dp = [STREAM
 * off=hb: DATA "hi"] (FIN). Returns hb (the byte offset of the DATA frame) and
 * the two frame lengths in hl and dl. This mirrors curl's POST on the wire. */
static usz lp_split_post_frames(
    u8* hp, usz hcap, usz* hl, u8* dp, usz dcap, usz* dl) {
  u8                       reqb[256];
  usz                      rlen = 0, hb;
  quic_stream_frame        sf;
  quic_h3_frame            hf   = {0};
  const u8*                body = (const u8*)"hi";
  wired_h3reqdrive_send_in in   = {
      quic_span_of((const u8*)"POST", 4), quic_span_of((const u8*)"/", 1),
      quic_span_of((const u8*)"h", 1), quic_span_of(body, 2)};
  quic_obuf rob = {reqb, sizeof reqb, 0};
  CHECK(wired_h3reqdrive_send_method(0, &in, &rob));
  rlen = rob.len;
  CHECK(quic_frame_get_stream(reqb, rlen, &sf) > 0);
  hb = quic_h3_frame_get(quic_span_of(sf.data, (usz)sf.length), &hf);
  CHECK(hb > 0 && hf.type == QUIC_H3_FRAME_HEADERS);
  CHECK(appdata_frame_flat(0, 0, sf.data, hb, 0, hp, hcap, hl));
  CHECK(appdata_frame_flat(
      0, hb, sf.data + hb, (usz)sf.length - hb, 1, dp, dcap, dl));
  return hb;
}

/* Build a POST on stream_id as two separate request STREAM frames split at
 * the HTTP/3 HEADERS/DATA boundary (like lp_split_post_frames, but for any
 * client bidi stream id, and any body — so two different streams' requests
 * can be told apart by their bodies in the same-slot-collision test below). */
static usz lp_split_post_frames_on(
    u64       stream_id,
    const u8* body,
    usz       body_len,
    u8*       hp,
    usz       hcap,
    usz*      hl,
    u8*       dp,
    usz       dcap,
    usz*      dl) {
  u8                       reqb[256];
  usz                      rlen = 0, hb;
  quic_stream_frame        sf;
  quic_h3_frame            hf = {0};
  wired_h3reqdrive_send_in in = {
      quic_span_of((const u8*)"POST", 4), quic_span_of((const u8*)"/", 1),
      quic_span_of((const u8*)"h", 1), quic_span_of(body, body_len)};
  quic_obuf rob = {reqb, sizeof reqb, 0};
  CHECK(wired_h3reqdrive_send_method(stream_id, &in, &rob));
  rlen = rob.len;
  CHECK(quic_frame_get_stream(reqb, rlen, &sf) > 0);
  hb = quic_h3_frame_get(quic_span_of(sf.data, (usz)sf.length), &hf);
  CHECK(hb > 0 && hf.type == QUIC_H3_FRAME_HEADERS);
  CHECK(appdata_frame_flat(stream_id, 0, sf.data, hb, 0, hp, hcap, hl));
  CHECK(appdata_frame_flat(
      stream_id, hb, sf.data + hb, (usz)sf.length - hb, 1, dp, dcap, dl));
  return hb;
}

/* TWO INDEPENDENT REQUEST STREAMS (RFC 9000 2.2, the property a single fixed
 * request slot could not have): stream 0's and stream 4's POSTs are each
 * split into HEADERS/DATA and interleaved across datagrams — stream 0's
 * HEADERS, then stream 4's HEADERS, then stream 4's DATA+FIN, then stream 0's
 * DATA+FIN. Each must decode with ITS OWN body, proving the two streams
 * reassemble into separate slots rather than clobbering a shared buffer. */
static void test_srvloop_two_streams_reassemble_independently(void) {
  struct lp_fix f;
  u8            h0[256], d0[256], h4[256], d4[256], out[1024], spkt[1024];
  usz           h0l, d0l, h4l, d4l, slen;
  quic_obuf     ob    = {out, sizeof out, 0};
  const u8*     body0 = (const u8*)"AA";
  const u8*     body4 = (const u8*)"BBB";
  lp_split_post_frames_on(
      0, body0, 2, h0, sizeof h0, &h0l, d0, sizeof d0, &d0l);
  lp_split_post_frames_on(
      4, body4, 3, h4, sizeof h4, &h4l, d4, sizeof d4, &d4l);
  lp_confirm(&f, &ob);
  /* datagram 1: stream 0's HEADERS only, then stream 4's HEADERS only -> no
   * request completes yet on either stream. */
  slen = client_seal_onertt_pn(&f, 3, h0, h0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  slen = client_seal_onertt_pn(&f, 4, h4, h4l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  /* datagram 3: stream 4's DATA+FIN completes stream 4's request with ITS
   * body ("BBB"), stream 0's slot is untouched. */
  slen = client_seal_onertt_pn(&f, 5, d4, d4l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 1);
  CHECK(
      f.l.req.body_len == 3 && f.l.req.body[0] == 'B' &&
      f.l.req.body[1] == 'B' && f.l.req.body[2] == 'B');
  /* datagram 4: stream 0's DATA+FIN completes stream 0's request with ITS OWN
   * body ("AA") — not stream 4's, and not corrupted by stream 4's slot. */
  slen = client_seal_onertt_pn(&f, 6, d0, d0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 1);
  CHECK(
      f.l.req.body_len == 2 && f.l.req.body[0] == 'A' &&
      f.l.req.body[1] == 'A');
}

/* draft-ietf-webtrans-http3-15 4.3: a WT bidi stream's stream_id has the same
 * low bits (00) as a normal client-initiated request stream, so it can only be
 * told apart by its leading bytes: the varint-encoded value 0x41 (2-byte wire
 * form {0x40, 0x41}, RFC 9000 16 — 65 exceeds the 1-byte range). Build stream
 * id's offset-0 STREAM frame with that leading varint plus one application
 * byte behind it. */
static usz lp_wt_bidi_stream(u8* out, usz cap, u64 stream_id) {
  u8                sig[3] = {0x40, 0x41, 'X'};
  quic_stream_frame sf     = {stream_id, 0, sizeof sig, sig, 0};
  return quic_frame_put_stream(out, cap, &sf);
}

/* STREAM ID CLASSIFICATION (draft-ietf-webtrans-http3-15 4.3): a stream
 * whose id classifies as a request (low bits 00) but whose leading bytes
 * decode to the WT_STREAM signal (0x41) must NOT be committed to the request-
 * reassembly path (no reassembly slot claimed for it), and a CONCURRENT
 * normal request stream (id 0) on the same connection must complete
 * unaffected — proving the WT stream did not corrupt or steal the other
 * stream's slot. Driven through wired_srvloop_step (the real per-datagram,
 * per-slot path — stream_slot_for/step_slot_for), not a direct dispatch call,
 * so the slot-claiming machinery itself is exercised. */
static void test_srvloop_wt_bidi_stream_not_request(void) {
  struct lp_fix f;
  u8            h0[256], d0[256], wt[64], out[1024], spkt[1024];
  usz           h0l, d0l, wtl, slen;
  quic_obuf     ob    = {out, sizeof out, 0};
  const u8*     body0 = (const u8*)"AA";
  lp_split_post_frames_on(
      0, body0, 2, h0, sizeof h0, &h0l, d0, sizeof d0, &d0l);
  wtl = lp_wt_bidi_stream(wt, sizeof wt, 4);
  lp_confirm(&f, &ob);
  /* datagram 1: stream 0's HEADERS, then stream 4's (WT) offset-0 signal
   * frame in the SAME payload -> no request completes yet, and the WT stream
   * must not have claimed a slot despite its id classifying as request-like. */
  {
    u8  payload[512];
    usz off = 0;
    for (usz i = 0; i < h0l; i++) payload[off++] = h0[i];
    for (usz i = 0; i < wtl; i++) payload[off++] = wt[i];
    slen = client_seal_onertt_pn(&f, 3, payload, off, spkt, sizeof spkt);
  }
  ob = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  /* only slot 0 (stream 0's) is claimed; no slot exists for stream 4. */
  CHECK(f.l.streams[0].in_use == 1 && f.l.streams[0].stream_id == 0);
  for (usz i = 1; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    CHECK(f.l.streams[i].in_use == 0);
  /* datagram 2: stream 0's DATA+FIN completes ITS OWN request, unaffected by
   * the WT stream's earlier frame in datagram 1. */
  slen = client_seal_onertt_pn(&f, 4, d0, d0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 1);
  CHECK(
      f.l.req.body_len == 2 && f.l.req.body[0] == 'A' &&
      f.l.req.body[1] == 'A');
  /* stream 4 still claimed no slot after the whole exchange. */
  for (usz i = 1; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    CHECK(f.l.streams[i].in_use == 0);
}

/* Build a STREAM frame at an explicit offset carrying `data` (used for the
 * post-signal continuation frames a WT bidi stream sends after its leading
 * 0x41 signal frame). */
static usz lp_stream_frame_at(
    u8*       out,
    usz       cap,
    u64       stream_id,
    u64       offset,
    const u8* data,
    usz       data_len,
    u8        fin) {
  quic_stream_frame sf = {stream_id, offset, data_len, data, fin};
  return quic_frame_put_stream(out, cap, &sf);
}

/* draft-ietf-webtrans-http3-15 4.3: a WT bidi stream's application bytes,
 * split across TWO STREAM frames like curl's HEADERS/DATA split — the
 * offset-0 signal frame (0x41, 2 bytes on the wire) immediately followed by
 * application bytes, then a SEPARATE offset>0 frame with more application
 * bytes and FIN. Confirms gather_wt_stream's reassembly lands the exact
 * application payload (not including the signal) into wt_streams[], and that
 * FIN is tracked. Driven through wired_srvloop_step, the real per-datagram
 * path (mirrors test_srvloop_wt_bidi_stream_not_request's own driving style).
 */
static void test_srvloop_wt_bidi_stream_reassembled(void) {
  struct lp_fix f;
  u8            f0[64], f1[64], out[1024], spkt[1024];
  usz           f0l, f1l, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  /* offset 0: 2-byte 0x41 signal ({0x40,0x41}) + "AB" application bytes. */
  const u8* sig_plus_ab = (const u8*)"\x40\x41" "AB";
  const u8* cd = (const u8*)"CD";
  f0l          = lp_stream_frame_at(f0, sizeof f0, 4, 0, sig_plus_ab, 4, 0);
  /* offset 4 on the WIRE == offset 2 in the post-signal application stream
   * (the 2-byte signal occupies wire offsets 0-1, "AB" occupies 2-3). */
  f1l = lp_stream_frame_at(f1, sizeof f1, 4, 4, cd, 2, 1);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, f0, f0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  slen = client_seal_onertt_pn(&f, 4, f1, f1l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  {
    int i = wired_srvloop_wt_slot_find(&f.l, 4);
    CHECK(i >= 0);
    CHECK(f.l.wt_streams[i].len == 4);
    CHECK(
        f.l.wt_streams[i].buf[0] == 'A' && f.l.wt_streams[i].buf[1] == 'B' &&
        f.l.wt_streams[i].buf[2] == 'C' && f.l.wt_streams[i].buf[3] == 'D');
    CHECK(f.l.wt_streams[i].fin == 1);
  }
}

/* 1 if some streams[] slot has claimed stream_id — the request-reassembly
 * table a WT bidi stream must NEVER appear in, at any offset. */
static int lp_streams_slot_claims(const wired_srvloop* l, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if (l->streams[i].in_use && l->streams[i].stream_id == stream_id) return 1;
  return 0;
}

/* REGRESSION (draft-ietf-webtrans-http3-15 4.3): a WT bidi stream's
 * post-signal CONTINUATION frame (offset>0) must be excluded from the
 * request-reassembly path exactly like its own offset-0 signal frame is --
 * sf_is_request must consult wt_frame_relevant (l->wt_streams[] membership),
 * not just the current frame's own offset. Before this was fixed, the
 * offset>0 frame's id-based classification alone made it look like a fresh
 * request stream: step_slot_for/wired_srvloop_payload_stream_id claimed a
 * streams[] slot for stream 4 and gather_request copied its bytes into that
 * slot's req_buf, alongside (not instead of) the correct wt_streams[]
 * landing. This reuses test_srvloop_wt_bidi_stream_reassembled's exact wire
 * shape and asserts the ADDITIONAL invariant that test didn't check: no
 * streams[] slot ever exists for stream 4. */
static void test_srvloop_wt_bidi_continuation_not_absorbed_into_request(void) {
  struct lp_fix f;
  u8            f0[64], f1[64], out[1024], spkt[1024];
  usz           f0l, f1l, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  const u8*     sig_plus_ab = (const u8*)"\x40\x41" "AB";
  const u8* cd = (const u8*)"CD";
  f0l          = lp_stream_frame_at(f0, sizeof f0, 4, 0, sig_plus_ab, 4, 0);
  f1l          = lp_stream_frame_at(f1, sizeof f1, 4, 4, cd, 2, 1);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, f0, f0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(!lp_streams_slot_claims(&f.l, 4));
  slen = client_seal_onertt_pn(&f, 4, f1, f1l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(!lp_streams_slot_claims(&f.l, 4));
  CHECK(f.l.got_request == 0);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    CHECK(f.l.streams[i].in_use == 0);
}

/* CONCURRENCY (draft-ietf-webtrans-http3-15 4.3): a WT bidi stream (id 4) and
 * a normal HTTP/3 request stream (id 0) on the SAME connection, coalesced into
 * the SAME payload/step, must both reassemble correctly into their own
 * separate tables (streams[] vs wt_streams[]) without interfering. */
static void test_srvloop_wt_stream_concurrent_with_request(void) {
  struct lp_fix f;
  u8            h0[256], d0[256], wt[64], out[1024], spkt[1024];
  usz           h0l, d0l, wtl, slen;
  quic_obuf     ob    = {out, sizeof out, 0};
  const u8*     body0 = (const u8*)"AA";
  lp_split_post_frames_on(
      0, body0, 2, h0, sizeof h0, &h0l, d0, sizeof d0, &d0l);
  wtl = lp_wt_bidi_stream(wt, sizeof wt, 4);
  lp_confirm(&f, &ob);
  /* datagram 1: stream 0's HEADERS + stream 4's WT signal, same payload. */
  {
    u8  payload[512];
    usz off = 0;
    for (usz i = 0; i < h0l; i++) payload[off++] = h0[i];
    for (usz i = 0; i < wtl; i++) payload[off++] = wt[i];
    slen = client_seal_onertt_pn(&f, 3, payload, off, spkt, sizeof spkt);
  }
  ob = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  /* the WT stream's slot exists (separate table), the request table has only
   * stream 0's slot -- neither corrupted the other. */
  {
    int i = wired_srvloop_wt_slot_find(&f.l, 4);
    CHECK(i >= 0);
    CHECK(f.l.wt_streams[i].len == 1 && f.l.wt_streams[i].buf[0] == 'X');
  }
  CHECK(f.l.streams[0].in_use == 1 && f.l.streams[0].stream_id == 0);
  /* datagram 2: stream 0's DATA+FIN completes ITS OWN request. */
  slen = client_seal_onertt_pn(&f, 4, d0, d0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 1);
  CHECK(
      f.l.req.body_len == 2 && f.l.req.body[0] == 'A' &&
      f.l.req.body[1] == 'A');
  /* the WT slot from datagram 1 is still intact, untouched by the request's
   * own completion. */
  {
    int i = wired_srvloop_wt_slot_find(&f.l, 4);
    CHECK(
        i >= 0 && f.l.wt_streams[i].len == 1 &&
        f.l.wt_streams[i].buf[0] == 'X');
  }
}

/* OFFSET-SKIP BOUNDARY (draft-ietf-webtrans-http3-15 4.3): the signal frame
 * carries ONLY the 1-byte-decoded-as-2-byte-wire signal varint, no
 * application bytes at all (length 2, exactly the signal's own wire size);
 * a SECOND frame at offset 2 carries the actual application data. Confirms
 * the reassembled buffer starts with the application data at buf[0] with no
 * off-by-one leak of the signal's own bytes. */
static void test_srvloop_wt_signal_only_frame_then_data(void) {
  struct lp_fix f;
  u8            f0[64], f1[64], out[1024], spkt[1024];
  usz           f0l, f1l, slen;
  quic_obuf     ob       = {out, sizeof out, 0};
  const u8*     sig_only = (const u8*)"\x40\x41"; /* signal, no app bytes */
  const u8*     app      = (const u8*)"Z";
  f0l = lp_stream_frame_at(f0, sizeof f0, 4, 0, sig_only, 2, 0);
  f1l = lp_stream_frame_at(f1, sizeof f1, 4, 2, app, 1, 1);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, f0, f0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  slen = client_seal_onertt_pn(&f, 4, f1, f1l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  {
    int i = wired_srvloop_wt_slot_find(&f.l, 4);
    CHECK(i >= 0);
    CHECK(f.l.wt_streams[i].len == 1);
    CHECK(f.l.wt_streams[i].buf[0] == 'Z'); /* NOT a leftover signal byte */
    CHECK(f.l.wt_streams[i].fin == 1);
  }
}

/* REGRESSION: a WT bidi stream arriving on a connection with no active
 * WebTransport session must not crash or corrupt state. This slice's
 * srvloop/dispatch layer does not know about wired_wt_session at all (the
 * association happens one layer up, in srvrun.c, gated on c->wt_active) -- so
 * from srvloop's own point of view there is nothing special to assert beyond
 * "reassembly still behaves exactly as the no-session-awareness tests above
 * already prove". This test pins that a dispatch_ctx with l set (the WT
 * gathering path IS active) but no session concept involved at all completes
 * without corrupting the connection's other state. */
static void test_srvloop_wt_stream_without_session_no_crash(void) {
  struct lp_fix f;
  u8            wt[64], out[1024], spkt[1024];
  usz           wtl, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  wtl              = lp_wt_bidi_stream(wt, sizeof wt, 4);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, wt, wtl, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  {
    int i = wired_srvloop_wt_slot_find(&f.l, 4);
    CHECK(
        i >= 0 && f.l.wt_streams[i].len == 1 &&
        f.l.wt_streams[i].buf[0] == 'X');
  }
  /* no other connection state disturbed: request table clean, no peer-close
   * latched. */
  CHECK(f.l.streams[0].in_use == 0);
  CHECK(f.l.peer_closed == 0);
}

/* draft-ietf-webtrans-http3-15 4.3: a WT uni stream's leading (offset-0)
 * bytes are the type varint 0x54 (2-byte wire form {0x40, 0x54}, RFC 9000
 * 16 — 84 exceeds the 1-byte range), unambiguously identifying the stream's
 * type with no signal/app-data ambiguity (unlike WT bidi's 0x41). Build
 * stream id's offset-0 STREAM frame with that leading varint plus one
 * application byte behind it. */
static usz lp_wt_uni_stream(u8* out, usz cap, u64 stream_id) {
  u8                sig[3] = {0x40, 0x54, 'X'};
  quic_stream_frame sf     = {stream_id, 0, sizeof sig, sig, 0};
  return quic_frame_put_stream(out, cap, &sf);
}

/* NEW UNI STREAM CLASSIFICATION (draft-ietf-webtrans-http3-15 4.3): a WT-typed
 * (0x54) client uni stream's post-type-byte application bytes are reassembled
 * into wt_uni_streams[], split across TWO STREAM frames like curl's HEADERS/
 * DATA split — the offset-0 type frame immediately followed by application
 * bytes, then a separate offset>0 frame with more bytes and FIN. Mirrors
 * test_srvloop_wt_bidi_stream_reassembled's own driving style/shape for the
 * separate uni table. */
static void test_srvloop_wt_uni_stream_reassembled(void) {
  struct lp_fix f;
  u8            f0[64], f1[64], out[1024], spkt[1024];
  usz           f0l, f1l, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  /* offset 0: 2-byte 0x54 type varint ({0x40,0x54}) + "AB" application bytes.
   */
  const u8* type_plus_ab = (const u8*)"\x40\x54" "AB";
  const u8* cd = (const u8*)"CD";
  f0l          = lp_stream_frame_at(f0, sizeof f0, 2, 0, type_plus_ab, 4, 0);
  /* offset 4 on the WIRE == offset 2 in the post-type application stream (the
   * 2-byte type varint occupies wire offsets 0-1, "AB" occupies 2-3). */
  f1l = lp_stream_frame_at(f1, sizeof f1, 2, 4, cd, 2, 1);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, f0, f0l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  slen = client_seal_onertt_pn(&f, 4, f1, f1l, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  {
    int i = wired_srvloop_wt_uni_slot_find(&f.l, 2);
    CHECK(i >= 0);
    CHECK(f.l.wt_uni_streams[i].len == 4);
    CHECK(
        f.l.wt_uni_streams[i].buf[0] == 'A' &&
        f.l.wt_uni_streams[i].buf[1] == 'B' &&
        f.l.wt_uni_streams[i].buf[2] == 'C' &&
        f.l.wt_uni_streams[i].buf[3] == 'D');
    CHECK(f.l.wt_uni_streams[i].fin == 1);
  }
}

/* REGRESSION: existing control (0x00)/QPACK (0x02/0x03) uni streams, now
 * newly CLASSIFIED (offset-0 type peeked) for the first time by this slice's
 * gather_uni_stream, still behave EXACTLY as before -- accepted (no crash,
 * no got_request), and critically no wt_uni_streams[] slot is claimed for any
 * of them (only a 0x54-typed stream ever claims one). Driven through the live
 * wired_srvloop_step path (ctx->l set), unlike the pre-existing direct-
 * dispatch test_srvloop_dispatch_uni_streams_not_request, so the classifier
 * added in THIS slice is actually exercised. */
static void test_srvloop_uni_control_qpack_still_ignored(void) {
  struct lp_fix f;
  u8            payload[256], out[1024], spkt[1024];
  usz           off = 0, slen;
  quic_obuf     ob  = {out, sizeof out, 0};
  off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
  off += lp_uni_stream(payload + off, sizeof payload - off, 6, 0x02);
  off += lp_uni_stream(payload + off, sizeof payload - off, 10, 0x03);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, payload, off, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  CHECK(f.l.peer_closed == 0);
  CHECK(wired_srvloop_wt_uni_slot_find(&f.l, 2) < 0);
  CHECK(wired_srvloop_wt_uni_slot_find(&f.l, 6) < 0);
  CHECK(wired_srvloop_wt_uni_slot_find(&f.l, 10) < 0);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    CHECK(f.l.wt_uni_streams[i].in_use == 0);
}

/* An unrecognized uni stream type (neither control/QPACK/WebTransport) does
 * not crash and falls back to accepted-and-ignored, exactly like the known
 * non-WT types above -- no slot claimed, no got_request, no peer_closed. */
static void test_srvloop_uni_unrecognized_type_no_crash(void) {
  struct lp_fix f;
  u8            payload[64], out[1024], spkt[1024];
  usz           off, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  off              = lp_uni_stream(payload, sizeof payload, 2, 0x7f);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, payload, off, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  CHECK(f.l.peer_closed == 0);
  CHECK(wired_srvloop_wt_uni_slot_find(&f.l, 2) < 0);
}

/* REGRESSION: a WT uni stream arriving on a connection with no active
 * WebTransport session must not crash or corrupt state -- mirrors
 * test_srvloop_wt_stream_without_session_no_crash for the separate uni table.
 * srvloop/dispatch does not know about wired_wt_session at all; the
 * association happens one layer up in srvrun.c, gated on c->wt_active. */
static void test_srvloop_wt_uni_stream_without_session_no_crash(void) {
  struct lp_fix f;
  u8            wt[64], out[1024], spkt[1024];
  usz           wtl, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  wtl              = lp_wt_uni_stream(wt, sizeof wt, 2);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, wt, wtl, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 0);
  {
    int i = wired_srvloop_wt_uni_slot_find(&f.l, 2);
    CHECK(
        i >= 0 && f.l.wt_uni_streams[i].len == 1 &&
        f.l.wt_uni_streams[i].buf[0] == 'X');
  }
  /* no other connection state disturbed: request table clean, no peer-close
   * latched, and the (structurally disjoint) WT bidi table untouched. */
  CHECK(f.l.streams[0].in_use == 0);
  CHECK(f.l.peer_closed == 0);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    CHECK(f.l.wt_streams[i].in_use == 0);
}

/* RFC 9221 5: a real encoded DATAGRAM frame, driven through the live
 * wired_srvloop_step path, lands its payload bytes in rx_datagrams[0] and
 * rx_datagram_n becomes 1. */
static void test_srvloop_datagram_queued_on_step(void) {
  struct lp_fix       f;
  u8                  payload[64], out[1024], spkt[1024];
  usz                 plen, slen;
  quic_obuf           ob = {out, sizeof out, 0};
  quic_datagram_frame df = {.length = 5, .data = (const u8*)"hello"};
  plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
  lp_confirm(&f, &ob);
  f.l.we_advertised_max_datagram = 100; /* RFC 9221 3: server opted in */
  slen = client_seal_onertt_pn(&f, 3, payload, plen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.rx_datagram_n == 1);
  CHECK(
      f.l.rx_datagrams[0].len == 5 && f.l.rx_datagrams[0].buf[0] == 'h' &&
      f.l.rx_datagrams[0].buf[1] == 'e' && f.l.rx_datagrams[0].buf[2] == 'l' &&
      f.l.rx_datagrams[0].buf[3] == 'l' && f.l.rx_datagrams[0].buf[4] == 'o');
}

/* RFC 9221 5: several DATAGRAM frames arriving across separate steps (separate
 * incoming packets) fill the queue in order up to
 * WIRED_SRVLOOP_MAX_RX_DATAGRAMS, and one more beyond capacity is dropped
 * (queue stays at max, earlier entries are not disturbed) -- the "drop
 * newest" overflow policy documented on rx_datagram_n. */
static void test_srvloop_datagram_queue_overflow_drops_newest(void) {
  struct lp_fix f;
  u8            payload[64], out[1024], spkt[1024];
  usz           plen, slen;
  quic_obuf     ob = {out, sizeof out, 0};
  usz           i;
  lp_confirm(&f, &ob);
  f.l.we_advertised_max_datagram = 100; /* RFC 9221 3: server opted in */
  /* fill the queue: WIRED_SRVLOOP_MAX_RX_DATAGRAMS datagrams, byte value i. */
  for (i = 0; i < WIRED_SRVLOOP_MAX_RX_DATAGRAMS; i++) {
    u8                  b  = (u8)('A' + i);
    quic_datagram_frame df = {.length = 1, .data = &b};
    plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
    slen = client_seal_onertt_pn(&f, 3 + i, payload, plen, spkt, sizeof spkt);
    ob   = (quic_obuf){out, sizeof out, 0};
    wired_srvloop_step(
        &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  }
  CHECK(f.l.rx_datagram_n == WIRED_SRVLOOP_MAX_RX_DATAGRAMS);
  for (i = 0; i < WIRED_SRVLOOP_MAX_RX_DATAGRAMS; i++)
    CHECK(
        f.l.rx_datagrams[i].len == 1 && f.l.rx_datagrams[i].buf[0] == 'A' + i);
  /* one more beyond capacity: dropped, queue stays at max, existing entries
   * untouched. */
  {
    u8                  b  = 'Z';
    quic_datagram_frame df = {.length = 1, .data = &b};
    plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
    slen = client_seal_onertt_pn(
        &f, 3 + WIRED_SRVLOOP_MAX_RX_DATAGRAMS, payload, plen, spkt,
        sizeof spkt);
    ob = (quic_obuf){out, sizeof out, 0};
    wired_srvloop_step(
        &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  }
  CHECK(f.l.rx_datagram_n == WIRED_SRVLOOP_MAX_RX_DATAGRAMS);
  for (i = 0; i < WIRED_SRVLOOP_MAX_RX_DATAGRAMS; i++)
    CHECK(
        f.l.rx_datagrams[i].len == 1 && f.l.rx_datagrams[i].buf[0] == 'A' + i);
}

/* RFC 9221 3: a DATAGRAM frame whose payload fits within the connection's own
 * advertised max_datagram_frame_size is accepted and queued normally --
 * equivalence-partition boundary "at the limit" (payload.n == advertised). */
static void test_srvloop_datagram_within_advertised_limit_accepted(void) {
  struct lp_fix       f;
  u8                  payload[64], out[1024], spkt[1024];
  usz                 plen, slen;
  quic_obuf           ob = {out, sizeof out, 0};
  u8                  data[50];
  quic_datagram_frame df = {.length = sizeof data, .data = data};
  for (usz i = 0; i < sizeof data; i++) data[i] = (u8)i;
  plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
  lp_confirm(&f, &ob);
  f.l.we_advertised_max_datagram = 100; /* RFC 9221 3: server opted in */
  slen = client_seal_onertt_pn(&f, 3, payload, plen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.rx_datagram_n == 1);
  CHECK(f.l.rx_datagrams[0].len == sizeof data);
  CHECK(f.l.datagram_violation == 0);
}

/* RFC 9221 3: a DATAGRAM frame whose payload EXCEEDS the connection's own
 * advertised max_datagram_frame_size is a PROTOCOL_VIOLATION -- rejected, not
 * queued, and the violation is latched for srvrun.c to close the connection
 * over. */
static void test_srvloop_datagram_exceeding_advertised_limit_rejected(void) {
  struct lp_fix       f;
  u8                  payload[512], out[1024], spkt[1024];
  usz                 plen, slen;
  quic_obuf           ob = {out, sizeof out, 0};
  u8                  data[200];
  quic_datagram_frame df = {.length = sizeof data, .data = data};
  for (usz i = 0; i < sizeof data; i++) data[i] = (u8)i;
  plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
  lp_confirm(&f, &ob);
  f.l.we_advertised_max_datagram = 100; /* RFC 9221 3: advertised limit 100 */
  slen = client_seal_onertt_pn(&f, 3, payload, plen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.rx_datagram_n == 0);
  CHECK(f.l.datagram_violation == 1);
}

/* RFC 9221 3: a connection that never advertised max_datagram_frame_size
 * (we_advertised_max_datagram == 0, this repo's "unset" sentinel) rejects ANY
 * received DATAGRAM frame as a PROTOCOL_VIOLATION -- the we_advertised=0
 * branch of quic_datagram_recv_ok, exercised via the live dispatch path. */
static void test_srvloop_datagram_without_advertising_rejected(void) {
  struct lp_fix       f;
  u8                  payload[64], out[1024], spkt[1024];
  usz                 plen, slen;
  quic_obuf           ob = {out, sizeof out, 0};
  quic_datagram_frame df = {.length = 5, .data = (const u8*)"hello"};
  plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
  lp_confirm(&f, &ob);
  /* f.l.we_advertised_max_datagram left at its wired_srvloop_init default: 0 */
  slen = client_seal_onertt_pn(&f, 3, payload, plen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.rx_datagram_n == 0);
  CHECK(f.l.datagram_violation == 1);
}

/* REGRESSION: a payload with only a request stream (no DATAGRAM) leaves
 * rx_datagram_n at 0 and the request path behaves exactly as before. */
static void test_srvloop_request_only_leaves_rx_datagrams_empty(void) {
  struct lp_fix f;
  u8            get[512], out[1024], spkt[1024];
  usz           glen, slen;
  quic_obuf     ob  = {out, sizeof out, 0};
  quic_obuf     gob = {get, sizeof get, 0};
  lp_confirm(&f, &ob);
  CHECK(wired_h3reqdrive_send_get(
      0,
      &(wired_h3reqdrive_get_in){
          quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
      &gob));
  glen = gob.len;
  slen = client_seal_onertt_pn(&f, 3, get, glen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.got_request == 1);
  CHECK(f.l.rx_datagram_n == 0);
}

/* REGRESSION: a normal request stream whose first application byte happens to
 * be 0x40 (a valid 2-byte varint PREFIX byte, but decoding to a value other
 * than 0x41 with the second byte below) must still classify as a request —
 * the signal check must match the full decoded varint VALUE, not merely
 * detect the 2-byte-varint prefix pattern. */
static void test_srvloop_stream_leading_0x40_not_wt_signal(void) {
  struct lp_fix            f;
  u8                       payload[256], reqb[256];
  usz                      rlen;
  wired_h3reqdrive_req     req;
  u8                       scratch[512];
  int                      got  = 0;
  const u8*                body = (const u8*)"hi";
  wired_h3reqdrive_send_in in   = {
      quic_span_of((const u8*)"POST", 4), quic_span_of((const u8*)"/", 1),
      quic_span_of((const u8*)"h", 1), quic_span_of(body, 2)};
  quic_obuf rob = {reqb, sizeof reqb, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  CHECK(wired_h3reqdrive_send_method(0, &in, &rob));
  rlen = rob.len;
  for (usz i = 0; i < rlen; i++) payload[i] = reqb[i];
  {
    wired_srvloop_reqacc      acc = lp_reqacc(&f.l);
    wired_srvloop_dispatch_in in2 = {
        quic_span_of(payload, rlen), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in2) == 1);
  }
  CHECK(got == 1);
  CHECK(req.body_len == 2 && req.body[0] == 'h' && req.body[1] == 'i');
}

/* RFC 9000 2.2 / RFC 9114 4.1: a POST whose HEADERS and DATA arrive as two
 * separate request STREAM frames in ONE datagram is reassembled in offset order
 * and the body recovered — not dropped as body 0. */
static void test_srvloop_dispatch_split_request_streams(void) {
  struct lp_fix        f;
  u8                   payload[512], scratch[512];
  usz                  hl, dl;
  wired_h3reqdrive_req req;
  int                  got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  /* HEADERS frame then DATA frame back to back in one payload. */
  lp_split_post_frames(
      payload, sizeof payload, &hl, payload + 256, sizeof payload - 256, &dl);
  for (usz i = 0; i < dl; i++) payload[hl + i] = payload[256 + i];
  {
    wired_srvloop_reqacc      acc = lp_reqacc(&f.l);
    wired_srvloop_dispatch_in in  = {
        quic_span_of(payload, hl + dl), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in) == 1);
  }
  CHECK(got == 1);
  CHECK(req.body_len == 2 && req.body[0] == 'h' && req.body[1] == 'i');
}

/* RFC 9000 2.2: curl's POST sends the HEADERS STREAM frame and the DATA STREAM
 * frame in SEPARATE datagrams (separate 1-RTT packets), so the server processes
 * them in separate dispatch calls. The first (HEADERS, no FIN) must NOT yet
 * decode a request; the second (DATA at the HEADERS' end offset, FIN) completes
 * the stream and the body is recovered — the real-curl failure that reported
 * body_len 0 because only one datagram was reassembled. */
static void test_srvloop_dispatch_split_across_datagrams(void) {
  struct lp_fix        f;
  u8                   hp[256], dp[256], scratch[512];
  usz                  hl, dl;
  wired_h3reqdrive_req req;
  int                  got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_split_post_frames(hp, sizeof hp, &hl, dp, sizeof dp, &dl);
  {
    wired_srvloop_reqacc acc = lp_reqacc(&f.l);
    /* datagram 1: HEADERS only, no FIN -> accumulated, no request yet. */
    wired_srvloop_dispatch_in in1 = {
        quic_span_of(hp, hl), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in1) == 1);
    CHECK(got == 0);
    /* datagram 2: DATA at offset hb, FIN -> request completes with body. */
    wired_srvloop_dispatch_in in2 = {
        quic_span_of(dp, dl), quic_mspan_of(scratch, sizeof scratch),
        lp_wrap0(&f.l), &got, &req};
    CHECK(
        wired_srvloop_dispatch(
            &(wired_srvloop_dispatch_ctx){&f.s, &f.l.h3, &acc, 0}, &in2) == 1);
  }
  CHECK(got == 1);
  CHECK(req.body_len == 2 && req.body[0] == 'h' && req.body[1] == 'i');
}

/* A test handler: echo the request body into body_out (RFC 9110 9.3.3 POST
 * semantics — the resource is the message). Also accumulates every body it
 * sees into a history buffer the GET case can return, exercising the contract
 * the example server relies on. */
static u8  g_test_history[256];
static usz g_test_history_len;

static int lp_echo_handler(
    void*                       ctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                content_type) {
  usz i;
  (void)ctx;
  (void)content_type;
  for (i = 0; i < req->body_len && i < body_out->cap; i++)
    body_out->p[i] = req->body[i];
  body_out->len = i;
  for (i = 0; i < req->body_len && g_test_history_len < sizeof g_test_history;
       i++)
    g_test_history[g_test_history_len++] = req->body[i];
  return 1;
}

/* Send a POST with `body` over 1-RTT and return the decoded response body via
 * the client decoder. Asserts a 200 with the echoed body reaches the client. */
static void lp_post_echo(struct lp_fix* f, const u8* body, usz blen) {
  u8               out[1024], reqb[512], spkt[1024];
  usz              rlen, slen;
  quic_obuf        ob = {out, sizeof out, 0}, rob = {reqb, sizeof reqb, 0};
  const u8*        pl;
  quic_h3conn_resp resp_out   = {0};
  wired_h3reqdrive_send_in in = {
      quic_span_of((const u8*)"POST", 4), quic_span_of((const u8*)"/", 1),
      quic_span_of((const u8*)"h", 1), quic_span_of(body, blen)};
  CHECK(wired_h3reqdrive_send_method(0, &in, &rob));
  rlen = rob.len;
  slen = client_seal_onertt(f, reqb, rlen, spkt, sizeof spkt);
  CHECK(
      wired_srvloop_step(
          &(wired_srvloop_conn){&f->l, &f->s}, quic_mspan_of(spkt, slen),
          &ob) == 1);
  CHECK(client_open_onertt(f, out, ob.len, &pl, &rlen) == 1);
  CHECK(quic_h3conn_recv_response(quic_span_of(pl, rlen), &resp_out) == 1);
  CHECK(resp_out.status == 200);
  CHECK(resp_out.body.n == blen);
  for (slen = 0; slen < blen; slen++)
    CHECK(resp_out.body.p[slen] == body[slen]);
}

/* HANDLER BODY ON THE WIRE (RFC 9110 9.3.3): with a handler registered, a POST
 * gets a 200 whose body is the echoed request body — proving the handler's
 * output reaches the sealed response, not the old body-less 200. */
static void test_srvloop_handler_body_echoed(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            out[1024];
  ob                 = (quic_obuf){out, sizeof out, 0};
  g_test_history_len = 0;
  lp_confirm(&f, &ob);
  wired_srvloop_set_handler(&f.l, lp_echo_handler, 0);
  lp_post_echo(&f, (const u8*)"hello", 5);
  /* history accumulates across POSTs (the GET case returns this). */
  lp_post_echo(&f, (const u8*)"world", 5);
  CHECK(g_test_history_len == 10);
  CHECK(g_test_history[0] == 'h' && g_test_history[9] == 'd');
}

/* Walk a 1-RTT payload for a CRYPTO frame (RFC 9000 19.6) carrying a
 * NewSessionTicket (RFC 8446 4.6.1) and return its sealed ticket bytes via
 * *sealed. Returns 1 if found. */
static int find_ticket_crypto(const u8* pl, usz pll, quic_span* sealed) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr)) {
    quic_crypto_frame cf;
    if (fr.type != QUIC_FRAME_CRYPTO) continue;
    if (quic_frame_get_crypto(fr.start, fr.remaining, &cf) == 0) continue;
    if (quic_tls_new_session_ticket_parse(
            quic_span_of(cf.data, cf.length), sealed))
      return 1;
  }
  return 0;
}

/* SESSION TICKET AT CONFIRMATION (RFC 8446 4.6.1): the very first confirmation
 * 1-RTT payload also carries a CRYPTO-framed NewSessionTicket the server just
 * sealed under its own fixed key, so a client is handed something it can later
 * present for resumption. */
static void test_srvloop_ticket_sent_on_confirm(void) {
  struct lp_fix f;
  u8            out[1500];
  quic_obuf     ob = {out, sizeof out, 0};
  const u8*     pkts[4];
  usz           offs[4], lens[4], np;
  const u8*     pl;
  usz           pll;
  quic_span     sealed;
  quic_ticket   opened;
  lp_confirm(&f, &ob);
  CHECK(f.l.ticket_sent == 1);
  /* The confirming datagram coalesces a long-header Handshake ACK ahead of the
   * 1-RTT packet (RFC 9000 12.2); split it before opening as 1-RTT. */
  quic_pktlist plist = {pkts, offs, lens, 4};
  np                 = quic_udploop_split(quic_span_of(out, ob.len), &plist);
  CHECK(np == 2);
  CHECK(client_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
  CHECK(find_ticket_crypto(pl, pll, &sealed) == 1);
  CHECK(quic_ticket_open(sealed, g_ticket_key, &opened) == 1);
}

/* NOT BEFORE CONFIRM: a datagram that has not yet driven the handshake to
 * confirmation must not carry a session ticket. */
static void test_srvloop_no_ticket_before_confirm(void) {
  struct lp_fix f;
  u8            out[1024];
  quic_obuf     ob = {out, sizeof out, 0};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  CHECK(f.l.ticket_sent == 0);
  (void)ob;
}

/* TICKET SENT EXACTLY ONCE: a second post-confirmation step (no new request)
 * must not re-emit the CRYPTO-framed ticket. */
static void test_srvloop_ticket_not_resent(void) {
  struct lp_fix f;
  u8            out[1024], junk[8] = {0};
  u8            spkt[1024];
  usz           slen;
  quic_obuf     ob = {out, sizeof out, 0};
  lp_confirm(&f, &ob);
  CHECK(f.l.ticket_sent == 1);
  slen = client_seal_onertt_pn(&f, 3, junk, sizeof junk, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  if (ob.len > 0) {
    const u8* pl;
    usz       pll;
    quic_span sealed;
    CHECK(client_open_onertt(&f, out, ob.len, &pl, &pll) == 1);
    CHECK(find_ticket_crypto(pl, pll, &sealed) == 0);
  }
}

/* PEER CLOSE DETECTION (RFC 9000 19.19): the payload scanner recognizes both
 * CONNECTION_CLOSE variants (0x1c transport, 0x1d application) and nothing
 * else. */
static void test_srvloop_close_frame_detected(void) {
  u8                    cc[32];
  u8                    ping[1] = {0x01};
  quic_conn_close_frame tpt     = {0, 0, 0, 0, 0};
  quic_conn_close_frame app     = {1, 0, 0, 0, 0};
  usz                   n = quic_frame_put_conn_close(cc, sizeof cc, &tpt);
  CHECK(n > 0);
  CHECK(srvloop_has_close(quic_span_of(cc, n)) == 1);
  n = quic_frame_put_conn_close(cc, sizeof cc, &app);
  CHECK(n > 0);
  CHECK(srvloop_has_close(quic_span_of(cc, n)) == 1);
  CHECK(srvloop_has_close(quic_span_of(ping, 1)) == 0);
}

/* PEER CLOSE OBSERVED (RFC 9000 10.2.2): a 1-RTT payload carrying a
 * CONNECTION_CLOSE marks the loop peer-closed; the ordinary confirm exchange
 * never does, and re-arming the loop clears the mark. */
static void test_srvloop_peer_close_sets_flag(void) {
  struct lp_fix         f;
  quic_obuf             ob;
  u8                    out[1024], cc[32], spkt[1024];
  usz                   ccn, slen;
  quic_conn_close_frame ccf = {0, 0, 0, 0, 0};
  ob                        = (quic_obuf){out, sizeof out, 0};
  lp_confirm(&f, &ob);
  CHECK(f.l.peer_closed == 0); /* normal handshake never sets it */
  ccn = quic_frame_put_conn_close(cc, sizeof cc, &ccf);
  CHECK(ccn > 0);
  slen = client_seal_onertt(&f, cc, ccn, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.peer_closed == 1);
  CHECK(wired_srvloop_init(&f.l, f.l.cli_scid, f.l.cli_scid_len) == 1);
  CHECK(f.l.peer_closed == 0); /* re-arm clears the mark */
}

/* ACK RANGES SURFACED (RFC 9000 19.3): ranges from an ACK frame in an opened
 * 1-RTT payload are copied to the loop's per-step list; a payload with no
 * ACK leaves the list empty (reset each step). */
static void test_srvloop_collects_ack_ranges(void) {
  struct lp_fix  f;
  quic_obuf      ob;
  u8             out[1024], fr[64], spkt[1024];
  usz            fl, slen;
  quic_ack_frame af = {0};
  ob                = (quic_obuf){out, sizeof out, 0};
  lp_confirm(&f, &ob);
  /* no ACK in anything so far this step path */
  {
    u8 ping[1] = {0x01};
    slen       = client_seal_onertt(&f, ping, 1, spkt, sizeof spkt);
    ob         = (quic_obuf){out, sizeof out, 0};
    wired_srvloop_step(
        &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
    CHECK(f.l.ack_n == 0);
  }
  af.n_ranges     = 2;
  af.ranges[0].hi = 9;
  af.ranges[0].lo = 7;
  af.ranges[1].hi = 4;
  af.ranges[1].lo = 4;
  fl              = quic_ack_encode(fr, sizeof fr, &af);
  CHECK(fl > 0);
  slen = client_seal_onertt(&f, fr, fl, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  CHECK(f.l.ack_n == 2);
  CHECK(f.l.ack_hi[0] == 9 && f.l.ack_lo[0] == 7);
  CHECK(f.l.ack_hi[1] == 4 && f.l.ack_lo[1] == 4);
}

/* RESPONSE TAKEOVER: with resp_external set, a decoded GET produces no 200
 * from the loop (the caller owns the response); the request itself is
 * latched and readable, and re-arming clears the takeover state. */
static void test_srvloop_external_resp_suppresses_200(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            out[1024], get[512], spkt[1024];
  usz           glen, slen;
  ob = (quic_obuf){out, sizeof out, 0};
  lp_confirm(&f, &ob);
  f.l.resp_external = 1;
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
  ob   = (quic_obuf){out, sizeof out, 0};
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, quic_mspan_of(spkt, slen), &ob);
  /* the request reached the caller... */
  CHECK(f.l.got_request == 1);
  CHECK(f.l.req.path_len == 1 && f.l.req.path[0] == '/');
  /* ...and the loop's reply (if any) carries no HTTP/3 response */
  if (ob.len) {
    const u8*        pl;
    usz              pll;
    quic_h3conn_resp resp_out = {0};
    CHECK(client_open_onertt(&f, out, ob.len, &pl, &pll) == 1);
    CHECK(quic_h3conn_recv_response(quic_span_of(pl, pll), &resp_out) == 0);
  }
  /* re-arm clears takeover state */
  CHECK(wired_srvloop_init(&f.l, f.l.cli_scid, f.l.cli_scid_len) == 1);
  CHECK(f.l.resp_external == 0 && f.l.got_request == 0 && f.l.ack_n == 0);
}

void test_srvloop(void) {
  test_srvloop_handler_body_echoed();
  test_srvloop_close_frame_detected();
  test_srvloop_peer_close_sets_flag();
  test_srvloop_collects_ack_ranges();
  test_srvloop_external_resp_suppresses_200();
  test_srvloop_dispatch_uni_streams_not_request();
  test_srvloop_dispatch_get_after_uni_streams();
  test_srvloop_dispatch_split_request_streams();
  test_srvloop_dispatch_split_across_datagrams();
  test_srvloop_two_streams_reassemble_independently();
  test_srvloop_wt_bidi_stream_not_request();
  test_srvloop_wt_bidi_stream_reassembled();
  test_srvloop_wt_bidi_continuation_not_absorbed_into_request();
  test_srvloop_wt_stream_concurrent_with_request();
  test_srvloop_wt_signal_only_frame_then_data();
  test_srvloop_wt_stream_without_session_no_crash();
  test_srvloop_wt_uni_stream_reassembled();
  test_srvloop_uni_control_qpack_still_ignored();
  test_srvloop_uni_unrecognized_type_no_crash();
  test_srvloop_wt_uni_stream_without_session_no_crash();
  test_srvloop_datagram_queued_on_step();
  test_srvloop_datagram_queue_overflow_drops_newest();
  test_srvloop_datagram_within_advertised_limit_accepted();
  test_srvloop_datagram_exceeding_advertised_limit_rejected();
  test_srvloop_datagram_without_advertising_rejected();
  test_srvloop_request_only_leaves_rx_datagrams_empty();
  test_srvloop_stream_leading_0x40_not_wt_signal();
  test_srvloop_send_initial_roundtrip();
  test_srvloop_wrong_direction_open_fails();
  test_srvloop_no_onertt_seal_before_confirm();
  test_srvloop_forged_finished_no_promote();
  test_srvloop_full_roundtrip();
  test_srvloop_response_dcid_is_client_scid();
  test_srvloop_dispatch_padding_before_crypto();
  test_srvloop_padding_before_stream();
  test_srvloop_coalesced_finished_behind_leading();
  test_srvloop_onertt_get_is_acked();
  test_srvloop_handshake_ack_tracks_pn();
  test_srvloop_confirm_and_200_coalesce();
  test_srvloop_confirm_emitted_once();
  test_srvloop_ticket_sent_on_confirm();
  test_srvloop_no_ticket_before_confirm();
  test_srvloop_ticket_not_resent();
}
