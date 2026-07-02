#include "app/http3/server/srvloop/srvloop.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/response.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvwire/wire.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/kdf/keys/keyset.h"
#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/keys/schedule_drive/keyschedule.h"
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

/* View a loop's cross-datagram request-stream accumulator (RFC 9000 2.2), so a
 * direct quic_srvloop_dispatch call reassembles into the loop's own buffer. */
static quic_srvloop_reqacc lp_reqacc(quic_srvloop *l) {
  quic_srvloop_reqacc acc;
  acc.buf  = l->req_buf;
  acc.cap  = sizeof l->req_buf;
  acc.len  = &l->req_len;
  acc.fin  = &l->req_fin;
  acc.done = &l->req_done;
  return acc;
}

/* Minimal Ed25519 end-entity cert carrying pub in its SPKI (RFC 5280 4.1). */
static usz lp_ed_cert(u8 *out, const u8 pub[32]) {
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

struct lp_fix {
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

static void lp_make_client_hello(struct lp_fix *f) {
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
static void lp_drive_to_flight(struct lp_fix *f) {
  u8        srv_priv[32], srv_pub[32], cert_seed[32], cert_pub[32];
  static u8 cert[128];
  usz       cert_len;
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);
  CHECK(quic_ed25519_keypair(cert_seed, cert_pub));
  cert_len = lp_ed_cert(cert, cert_pub);

  quic_server_init(&f->s, srv_priv, srv_pub, cert_seed, cert, cert_len);
  CHECK(quic_server_set_cids(&f->s, g_cli_scid, 6, g_cli_scid, 6) == 1);
  CHECK(quic_srvloop_init(&f->l, g_cli_scid, 6) == 1);
  CHECK(quic_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
  CHECK(
      quic_server_build_flight(
          &f->s, f->srv_random, f->sh, sizeof(f->sh), &f->sh_len, f->flight,
          sizeof(f->flight), &f->flight_len) == 1);
  CHECK(f->s.phase == QUIC_SERVER_HS_FLIGHT_SENT);
}

/* Compute the genuine client Finished message (RFC 8446 4.4.4). */
static void lp_make_client_finished(struct lp_fix *f) {
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
    struct lp_fix *f, const u8 *msg, usz mlen, u8 *pkt, usz cap) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  CHECK(quic_srvwire_seal_handshake(
      k, &hp, f->s.sdrv.iscid, f->s.sdrv.iscid_len, g_cli_scid, 6, 0, -1, msg,
      mlen, pkt, cap, &total));
  return total;
}

/* Client role: seal a Handshake packet at an explicit packet number. curl does
 * not send its Finished at PN 0 — it leads with an ACK-only Handshake packet,
 * so the Finished lands at a later PN. */
static usz client_seal_handshake_pn(
    struct lp_fix *f, u64 pn, const u8 *msg, usz mlen, u8 *pkt, usz cap) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  usz                      total = 0;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  CHECK(quic_srvwire_seal_handshake(
      k, &hp, f->s.sdrv.iscid, f->s.sdrv.iscid_len, g_cli_scid, 6, pn, -1, msg,
      mlen, pkt, cap, &total));
  return total;
}

/* Client role: seal a 1-RTT STREAM payload toward the server with CLIENT_AP. */
static usz client_seal_onertt(
    struct lp_fix *f, const u8 *pl, usz pln, u8 *pkt, usz cap) {
  const quic_initial_keys *k;
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
  usz           total   = 0;
  const u8     *tls     = 0;
  usz           tls_len = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  CHECK(quic_srvloop_send_initial(
      &f.s, g_cli_scid, 6, 1, -1, f.sh, f.sh_len, pkt, sizeof pkt, &total));
  /* RFC 9000 14.1: the Initial datagram is padded to >= 1200, else curl drops
   * it and PTO-retransmits its own Initial for ~4s (the appconnect stall). */
  CHECK(total >= 1200);
  CHECK(quic_srvwire_open_initial(
      f.s.sdrv.odcid, f.s.sdrv.odcid_len, pkt, total, 1, &tls, &tls_len));
  CHECK(tls_len == f.sh_len); /* PADDING after CRYPTO is ignored on open */
}

/* DIRECTION SAFETY: a server-sealed Handshake packet (SERVER_HS) opens with the
 * server's own-direction key (the client's peer key) but NOT with CLIENT_HS,
 * the peer-direction key the server itself uses to open inbound packets. */
static void test_srvloop_wrong_direction_open_fails(void) {
  struct lp_fix            f;
  u8                       pkt[2300];
  usz                      total = 0;
  const quic_initial_keys *own, *peer;
  quic_aes128              ownhp, peerhp;
  const u8                *tls     = 0;
  usz                      tls_len = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  CHECK(quic_srvloop_send_handshake(
      &f.s, g_cli_scid, 6, 0, -1, f.flight, f.flight_len, pkt, sizeof pkt,
      &total));
  /* SERVER_HS (own / client-peer) opens it; CLIENT_HS (server-open) must NOT.
   */
  CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_HS, &own) == 1);
  quic_aes128_init(&ownhp, own->hp);
  CHECK(
      quic_srvwire_open_handshake(own, &ownhp, pkt, total, 6, &tls, &tls_len) ==
      1);
  CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_CLIENT_HS, &peer) == 1);
  quic_aes128_init(&peerhp, peer->hp);
  CHECK(
      quic_srvwire_open_handshake(
          peer, &peerhp, pkt, total, 6, &tls, &tls_len) == 0);
}

/* No 1-RTT key before confirmation: seal at 1-RTT is refused (RFC 9001 5). */
static void test_srvloop_no_onertt_seal_before_confirm(void) {
  struct lp_fix f;
  u8            pkt[256], frame[1] = {0x1e};
  usz           total = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  CHECK(quic_server_is_confirmed(&f.s) == 0);
  CHECK(
      quic_srvloop_send_onertt(
          &f.s, g_cli_scid, 6, 0, frame, 1, pkt, sizeof pkt, &total) == 0);
}

/* CENTRAL SAFETY: a forged client Finished does not promote the server, so the
 * step produces no HANDSHAKE_DONE and 1-RTT stays unarmed. */
static void test_srvloop_forged_finished_no_promote(void) {
  struct lp_fix f;
  u8            cpkt[512], out[512];
  usz           clen, out_len = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  f.cli_fin[4] ^= 0x01;
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out, &out_len) ==
      0);
  CHECK(quic_server_is_confirmed(&f.s) == 0);
  {
    const quic_initial_keys *k;
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
  }
}

/* Client role: open a server-sealed 1-RTT packet with the peer SERVER_AP key
 * (the client's view) and view its raw frame payload. */
static int client_open_onertt(
    struct lp_fix *f, u8 *pkt, usz len, const u8 **pl, usz *pll) {
  const quic_initial_keys *k;
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
static void check_settings_and_done(const u8 *pl, usz pll) {
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
  usz           clen, out_len = 0, glen;
  const u8     *pkts[4];
  usz           offs[4], lens[4], np;
  quic_pktlist  plist = {pkts, offs, lens, 4};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out, &out_len) ==
      1);
  CHECK(quic_server_is_confirmed(&f.s) == 1);
  /* The reply coalesces a Handshake ACK (long header) and a 1-RTT packet. */
  np = quic_udploop_split(quic_span_of(out, out_len), &plist);
  CHECK(np == 2);
  CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
  {
    const u8 *pl;
    usz       pll;
    CHECK(client_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
    check_settings_and_done(pl, pll);
  }

  /* GET over 1-RTT -> a 200 response that the client can decode. */
  CHECK(quic_h3reqdrive_send_get(
      0, (const u8 *)"/", 1, (const u8 *)"h", 1, get, sizeof get, &glen));
  {
    u8        spkt[1024];
    usz       slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
    const u8 *pl, *body;
    usz       pll, body_len;
    u16       status = 0;
    out_len          = 0;
    CHECK(
        quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len) ==
        1);
    CHECK(client_open_onertt(&f, out, out_len, &pl, &pll) == 1);
    CHECK(quic_h3conn_recv_response(pl, pll, &status, &body, &body_len) == 1);
    CHECK(status == 200);
  }
}

/* RFC 9000 17.3: the DCID of a short-header packet is out[1 .. 1+len], in the
 * clear (header protection masks only byte0 and the packet number). */
static int onertt_dcid_is(const u8 *pkt, const u8 *cid, u8 len) {
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
  usz             clen, out_len = 0;
  const u8       *pkts[4];
  usz             offs[4], lens[4], np;
  quic_pktlist  plist = {pkts, offs, lens, 4};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  /* re-seed the loop with the client's SCID (distinct from g_cli_scid). */
  CHECK(quic_srvloop_init(&f.l, cli_scid, 6) == 1);
  lp_make_client_finished(&f);
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out, &out_len) ==
      1);
  np = quic_udploop_split(quic_span_of(out, out_len), &plist);
  CHECK(np == 2);                                    /* Handshake ACK + 1-RTT */
  CHECK(onertt_dcid_is(out + offs[1], cli_scid, 6)); /* DCID == client SCID */
  CHECK(
      !onertt_dcid_is(out + offs[1], g_cli_scid, 6)); /* NOT the client DCID */
}

/* Client role: seal a 1-RTT STREAM payload at an explicit packet number. */
static usz client_seal_onertt_pn(
    struct lp_fix *f, u64 pn, const u8 *pl, usz pln, u8 *pkt, usz cap) {
  const quic_initial_keys *k;
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
static void check_acks_pn(const u8 *pl, usz pll, u64 pn) {
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
static void lp_confirm(struct lp_fix *f, u8 *out, usz cap, usz *out_len) {
  u8  cpkt[1024];
  usz clen;
  lp_make_client_hello(f);
  lp_drive_to_flight(f);
  lp_make_client_finished(f);
  clen =
      client_seal_handshake(f, f->cli_fin, f->cli_fin_len, cpkt, sizeof cpkt);
  *out_len = 0;
  CHECK(quic_srvloop_step(&f->l, &f->s, cpkt, clen, out, cap, out_len) == 1);
  CHECK(quic_server_is_confirmed(&f->s) == 1);
}

/* (C) ACK A 1-RTT GET: a decoded GET yields a 200 whose 1-RTT packet also
 * carries an ACK of the received GET's packet number (RFC 9000 13.2.1), so the
 * client stops retransmitting the GET once the 200 is received. */
static void test_srvloop_onertt_get_is_acked(void) {
  struct lp_fix f;
  u8            out[1024], get[512], spkt[1024];
  usz           out_len = 0, glen, slen;
  const u8     *pl;
  usz           pll;
  lp_confirm(&f, out, sizeof out, &out_len);
  CHECK(quic_h3reqdrive_send_get(
      0, (const u8 *)"/", 1, (const u8 *)"h", 1, get, sizeof get, &glen));
  slen    = client_seal_onertt_pn(&f, 7, get, glen, spkt, sizeof spkt);
  out_len = 0;
  CHECK(
      quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len) ==
      1);
  CHECK(client_open_onertt(&f, out, out_len, &pl, &pll) == 1);
  check_acks_pn(pl, pll, 7);
}

/* Open a server-sealed Handshake packet with the client's peer key (SERVER_HS)
 * and return its raw decrypted frame payload (quic_hspkt_open, not srvwire's
 * CRYPTO extractor — the ACK-only flight carries no CRYPTO frame). */
static int client_open_handshake(
    struct lp_fix *f, const u8 *pkt, usz len, const u8 **pl, usz *pll) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_SERVER_HS, &k) == 1);
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys pk = {k, &hp};
  quic_span         v;
  if (!quic_hspkt_open(&pk, quic_mspan_of((u8 *)pkt, len), &v)) return 0;
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
  usz           clen, out_len = 0;
  const u8     *pkts[4], *pl;
  usz           offs[4], lens[4], np, pll;
  quic_pktlist  plist = {pkts, offs, lens, 4};
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  clen = client_seal_handshake_pn(
      &f, 3, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out, &out_len) ==
      1);
  np = quic_udploop_split(quic_span_of(out, out_len), &plist);
  CHECK(np == 2);
  CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
  CHECK(client_open_handshake(&f, out + offs[0], lens[0], &pl, &pll) == 1);
  check_acks_pn(pl, pll, 3); /* ACKs the Finished's PN 3, not the fixed 0 */
}

/* Walk a 1-RTT payload and assert it carries all three: the control-stream
 * SETTINGS (id 3), a HANDSHAKE_DONE (0x1e), and a decodable 200 on the request
 * stream (id 0) — regardless of frame order (RFC 9114 6.2.1 / 4.1, RFC 9000
 * 19.20). The 200's STREAM frame (type byte onward) is fed to recv_response. */
static void check_confirm_and_200_payload(const u8 *pl, usz pll) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  int                 settings = 0, done = 0, ok200 = 0;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr)) {
    u64               type  = fr.type;
    const u8         *frame = fr.start;
    usz               rem   = fr.remaining;
    quic_stream_frame sf;
    const u8         *body;
    usz               body_len;
    u16               status = 0;
    if (type == 0x1e) done = 1;
    if (type < 0x08 || type > 0x0f || !quic_frame_get_stream(frame, rem, &sf))
      continue;
    if (sf.stream_id == 3) settings = 1;
    if (sf.stream_id == 0 &&
        quic_h3conn_recv_response(frame, rem, &status, &body, &body_len) &&
        status == 200)
      ok200 = 1;
  }
  CHECK(settings && done && ok200);
}

/* Confirm the server by dispatching its Finished directly (deriving the 1-RTT
 * keys) WITHOUT running produce, so the confirmation has not yet been sealed:
 * s->hs_done_sent and the loop latches stay 0. This sets up the same internal
 * state curl reaches when it coalesces its Finished and GET in one datagram. */
static void lp_confirm_via_dispatch(struct lp_fix *f) {
  u8                  scratch[512];
  quic_h3reqdrive_req req;
  int                 got = 0;
  quic_crypto_frame   cf;
  u8                  payload[256];
  usz                 plen;
  lp_make_client_hello(f);
  lp_drive_to_flight(f);
  lp_make_client_finished(f);
  cf.offset = 0;
  cf.length = f->cli_fin_len;
  cf.data   = f->cli_fin;
  plen      = quic_frame_put_crypto(payload, sizeof payload, &cf);
  {
    quic_srvloop_reqacc acc = lp_reqacc(&f->l);
    CHECK(
        quic_srvloop_dispatch(
            &f->s, &f->l.h3, payload, plen, &acc, scratch, sizeof scratch, &got,
            &req) == 1);
  }
  CHECK(quic_server_is_confirmed(&f->s) == 1);
}

/* COALESCED CONFIRM + 200 (RFC 9000 12.2, RFC 9114 6.2.1): when one datagram
 * both confirms the handshake AND carries a GET, the reply coalesces the
 * confirmation (1-RTT SETTINGS + HANDSHAKE_DONE) with the 1-RTT 200 — so curl
 * receives SETTINGS to establish HTTP/3 and never gets the 200 alone with
 * SETTINGS still missing. */
static void test_srvloop_confirm_and_200_coalesce(void) {
  struct lp_fix f;
  u8            out[1500], get[512], spkt[1024];
  usz           glen, slen, out_len = 0;
  const u8     *pkts[4];
  usz           offs[4], lens[4], np;
  quic_pktlist  plist = {pkts, offs, lens, 4};
  lp_confirm_via_dispatch(&f);
  CHECK(f.l.hs_done_sent == 0); /* confirmation not yet sealed */
  CHECK(quic_h3reqdrive_send_get(
      0, (const u8 *)"/", 1, (const u8 *)"h", 1, get, sizeof get, &glen));
  slen    = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
  out_len = 0;
  CHECK(
      quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len) ==
      1);
  /* Reply: [Handshake ACK (long)][one 1-RTT packet: SETTINGS + HANDSHAKE_DONE
   * + 200]. Short-header packets carry no length, so confirm and 200 share a
   * single 1-RTT payload rather than two coalesced 1-RTT packets. */
  np = quic_udploop_split(quic_span_of(out, out_len), &plist);
  CHECK(np == 2);
  CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
  {
    const u8 *pl;
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
  usz out_len = 0, slen;
  lp_confirm(&f, out, sizeof out, &out_len);
  /* A 1-RTT packet that carries only PADDING: no request decoded. */
  slen    = client_seal_onertt_pn(&f, 3, junk, sizeof junk, spkt, sizeof spkt);
  out_len = 0;
  quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len);
  if (out_len > 0) {
    const u8 *pl;
    usz       pll;
    CHECK(client_open_onertt(&f, out, out_len, &pl, &pll) == 1);
    /* must not be the confirmation: no HANDSHAKE_DONE trailer. */
    CHECK(!(pll > 0 && pl[pll - 1] == 0x1e));
  }
}

/* Prepend a PADDING (0x00) byte to src into dst; returns the new length. */
static usz lp_pad_prefix(u8 *dst, const u8 *src, usz n) {
  dst[0] = 0x00; /* RFC 9000 19.1 PADDING */
  for (usz i = 0; i < n; i++) dst[1 + i] = src[i];
  return n + 1;
}

/* Build a dispatcher payload [PADDING][CRYPTO(msg)] (RFC 9000 12.4 / 19.6). */
static usz lp_padding_then_crypto(u8 *out, usz cap, const u8 *msg, usz mlen) {
  quic_crypto_frame cf = {0, (u64)mlen, msg};
  out[0]               = 0x00; /* leading PADDING, as curl/quiche emit */
  return 1 + quic_frame_put_crypto(out + 1, cap - 1, &cf);
}

/* NON-CRYPTO-FIRST handshake: a Handshake payload that leads with PADDING
 * before its CRYPTO frame (curl/quiche do this) must still confirm. The
 * dispatcher is exercised directly because the wire helper wraps everything in
 * one CRYPTO frame (RFC 9000 12.4). */
static void test_srvloop_dispatch_padding_before_crypto(void) {
  struct lp_fix       f;
  u8                  payload[256];
  usz                 plen;
  quic_h3reqdrive_req req;
  u8                  scratch[512];
  int                 got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  plen =
      lp_padding_then_crypto(payload, sizeof payload, f.cli_fin, f.cli_fin_len);
  {
    quic_srvloop_reqacc acc = lp_reqacc(&f.l);
    CHECK(
        quic_srvloop_dispatch(
            &f.s, &f.l.h3, payload, plen, &acc, scratch, sizeof scratch, &got,
            &req) == 1);
  }
  CHECK(quic_server_is_confirmed(&f.s) == 1);
}

/* NON-STREAM-FIRST 1-RTT: a 1-RTT packet that leads with PADDING before the
 * STREAM frame still yields a 200 (RFC 9000 12.4). The full seal/open path is
 * used here since onertt carries the raw frame payload. */
static void test_srvloop_padding_before_stream(void) {
  struct lp_fix f;
  u8            cpkt[1024], out[1024], get[512], pget[576], spkt[1024];
  usz           clen, out_len = 0, glen, plen, slen;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
  CHECK(
      quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out, &out_len) ==
      1);
  CHECK(quic_h3reqdrive_send_get(
      0, (const u8 *)"/", 1, (const u8 *)"h", 1, get, sizeof get, &glen));
  plen    = lp_pad_prefix(pget, get, glen);
  slen    = client_seal_onertt(&f, pget, plen, spkt, sizeof spkt);
  out_len = 0;
  CHECK(
      quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len) ==
      1);
  CHECK(out_len > 0);
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
  usz           lead_len, rest_len, i, off = 0, out_len = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_make_client_finished(&f);
  lead_len = client_seal_handshake(&f, padding, 1, lead, sizeof lead);
  rest_len =
      client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, rest, sizeof rest);
  for (i = 0; i < lead_len; i++) dg[off++] = lead[i];
  for (i = 0; i < rest_len; i++) dg[off++] = rest[i];
  CHECK(quic_srvloop_step(&f.l, &f.s, dg, off, out, sizeof out, &out_len) == 1);
  CHECK(quic_server_is_confirmed(&f.s) == 1);
}

/* Build a STREAM frame on `stream_id` whose data is one type byte `lead`
 * (RFC 9114 6.2: control 0x00 / QPACK encoder 0x02 / decoder 0x03). */
static usz lp_uni_stream(u8 *out, usz cap, u64 stream_id, u8 lead) {
  quic_stream_frame sf = {stream_id, 0, 1, &lead, 0};
  return quic_frame_put_stream(out, cap, &sf);
}

/* STREAM ID CLASSIFICATION (RFC 9000 2.1, RFC 9114 6.2): a 1-RTT payload that
 * carries only unidirectional STREAM frames (curl's control/encoder/decoder,
 * ids 2 and 6) must be accepted without being mistaken for a request — no
 * got_request, no error. */
static void test_srvloop_dispatch_uni_streams_not_request(void) {
  struct lp_fix       f;
  u8                  payload[256];
  usz                 off = 0;
  quic_h3reqdrive_req req;
  u8                  scratch[512];
  int                 got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
  off += lp_uni_stream(payload + off, sizeof payload - off, 6, 0x02);
  {
    quic_srvloop_reqacc acc = lp_reqacc(&f.l);
    CHECK(
        quic_srvloop_dispatch(
            &f.s, &f.l.h3, payload, off, &acc, scratch, sizeof scratch, &got,
            &req) == 1);
  }
  CHECK(got == 0);
}

/* A client bidi request stream (id 0, HEADERS=GET) arriving AFTER leading
 * unidirectional streams is the one decoded: the dispatcher skips the uni
 * STREAMs and drives the request (RFC 9000 2.1, RFC 9114 6.1/6.2). */
static void test_srvloop_dispatch_get_after_uni_streams(void) {
  struct lp_fix       f;
  u8                  payload[576], get[512];
  usz                 off = 0, glen;
  quic_h3reqdrive_req req;
  u8                  scratch[512];
  int                 got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
  off += lp_uni_stream(payload + off, sizeof payload - off, 3, 0x03);
  CHECK(quic_h3reqdrive_send_get(
      0, (const u8 *)"/", 1, (const u8 *)"h", 1, get, sizeof get, &glen));
  for (usz i = 0; i < glen; i++) payload[off++] = get[i];
  {
    quic_srvloop_reqacc acc = lp_reqacc(&f.l);
    CHECK(
        quic_srvloop_dispatch(
            &f.s, &f.l.h3, payload, off, &acc, scratch, sizeof scratch, &got,
            &req) == 1);
  }
  CHECK(got == 1);
}

/* Build a POST as two separate request STREAM frames split at the HTTP/3
 * HEADERS/DATA boundary: hp = [STREAM off 0: HEADERS] (no FIN), dp = [STREAM
 * off=hb: DATA "hi"] (FIN). Returns hb (the byte offset of the DATA frame) and
 * the two frame lengths in hl and dl. This mirrors curl's POST on the wire. */
static usz lp_split_post_frames(
    u8 *hp, usz hcap, usz *hl, u8 *dp, usz dcap, usz *dl) {
  u8                reqb[256];
  usz               rlen = 0, hb;
  quic_stream_frame sf;
  u64               type = 0, plen = 0;
  const u8         *body = (const u8 *)"hi", *pl = 0;
  CHECK(quic_h3reqdrive_send_method(
      0, (const u8 *)"POST", 4, (const u8 *)"/", 1, (const u8 *)"h", 1, body, 2,
      reqb, sizeof reqb, &rlen));
  CHECK(quic_frame_get_stream(reqb, rlen, &sf) > 0);
  hb = quic_h3_frame_get(sf.data, (usz)sf.length, &type, &pl, &plen);
  CHECK(hb > 0 && type == QUIC_H3_FRAME_HEADERS);
  CHECK(quic_appdata_stream_frame(0, 0, sf.data, hb, 0, hp, hcap, hl));
  CHECK(quic_appdata_stream_frame(
      0, hb, sf.data + hb, (usz)sf.length - hb, 1, dp, dcap, dl));
  return hb;
}

/* RFC 9000 2.2 / RFC 9114 4.1: a POST whose HEADERS and DATA arrive as two
 * separate request STREAM frames in ONE datagram is reassembled in offset order
 * and the body recovered — not dropped as body 0. */
static void test_srvloop_dispatch_split_request_streams(void) {
  struct lp_fix       f;
  u8                  payload[512], scratch[512];
  usz                 hl, dl;
  quic_h3reqdrive_req req;
  int                 got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  /* HEADERS frame then DATA frame back to back in one payload. */
  lp_split_post_frames(
      payload, sizeof payload, &hl, payload + 256, sizeof payload - 256, &dl);
  for (usz i = 0; i < dl; i++) payload[hl + i] = payload[256 + i];
  {
    quic_srvloop_reqacc acc = lp_reqacc(&f.l);
    CHECK(
        quic_srvloop_dispatch(
            &f.s, &f.l.h3, payload, hl + dl, &acc, scratch, sizeof scratch,
            &got, &req) == 1);
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
  struct lp_fix       f;
  u8                  hp[256], dp[256], scratch[512];
  usz                 hl, dl;
  quic_h3reqdrive_req req;
  int                 got = 0;
  lp_make_client_hello(&f);
  lp_drive_to_flight(&f);
  lp_split_post_frames(hp, sizeof hp, &hl, dp, sizeof dp, &dl);
  {
    quic_srvloop_reqacc acc = lp_reqacc(&f.l);
    /* datagram 1: HEADERS only, no FIN -> accumulated, no request yet. */
    CHECK(
        quic_srvloop_dispatch(
            &f.s, &f.l.h3, hp, hl, &acc, scratch, sizeof scratch, &got, &req) ==
        1);
    CHECK(got == 0);
    /* datagram 2: DATA at offset hb, FIN -> request completes with body. */
    CHECK(
        quic_srvloop_dispatch(
            &f.s, &f.l.h3, dp, dl, &acc, scratch, sizeof scratch, &got, &req) ==
        1);
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
    void                      *ctx,
    const quic_h3reqdrive_req *req,
    u8                        *body_out,
    usz                        cap,
    usz                       *body_len) {
  usz i;
  (void)ctx;
  for (i = 0; i < req->body_len && i < cap; i++) body_out[i] = req->body[i];
  *body_len = i;
  for (i = 0; i < req->body_len && g_test_history_len < sizeof g_test_history;
       i++)
    g_test_history[g_test_history_len++] = req->body[i];
  return 1;
}

/* Send a POST with `body` over 1-RTT and return the decoded response body via
 * the client decoder. Asserts a 200 with the echoed body reaches the client. */
static void lp_post_echo(struct lp_fix *f, const u8 *body, usz blen) {
  u8        out[1024], reqb[512], spkt[1024];
  usz       out_len = 0, rlen, slen, rb_len;
  const u8 *pl, *rb;
  u16       status = 0;
  CHECK(quic_h3reqdrive_send_method(
      0, (const u8 *)"POST", 4, (const u8 *)"/", 1, (const u8 *)"h", 1, body,
      blen, reqb, sizeof reqb, &rlen));
  slen = client_seal_onertt(f, reqb, rlen, spkt, sizeof spkt);
  CHECK(
      quic_srvloop_step(&f->l, &f->s, spkt, slen, out, sizeof out, &out_len) ==
      1);
  CHECK(client_open_onertt(f, out, out_len, &pl, &rlen) == 1);
  CHECK(quic_h3conn_recv_response(pl, rlen, &status, &rb, &rb_len) == 1);
  CHECK(status == 200);
  CHECK(rb_len == blen);
  for (slen = 0; slen < blen; slen++) CHECK(rb[slen] == body[slen]);
  (void)out_len;
}

/* HANDLER BODY ON THE WIRE (RFC 9110 9.3.3): with a handler registered, a POST
 * gets a 200 whose body is the echoed request body — proving the handler's
 * output reaches the sealed response, not the old body-less 200. */
static void test_srvloop_handler_body_echoed(void) {
  struct lp_fix f;
  u8            out[1024];
  usz           out_len = 0;
  g_test_history_len    = 0;
  lp_confirm(&f, out, sizeof out, &out_len);
  quic_srvloop_set_handler(&f.l, lp_echo_handler, 0);
  lp_post_echo(&f, (const u8 *)"hello", 5);
  /* history accumulates across POSTs (the GET case returns this). */
  lp_post_echo(&f, (const u8 *)"world", 5);
  CHECK(g_test_history_len == 10);
  CHECK(g_test_history[0] == 'h' && g_test_history[9] == 'd');
}

void test_srvloop(void) {
  test_srvloop_handler_body_echoed();
  test_srvloop_dispatch_uni_streams_not_request();
  test_srvloop_dispatch_get_after_uni_streams();
  test_srvloop_dispatch_split_request_streams();
  test_srvloop_dispatch_split_across_datagrams();
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
}
