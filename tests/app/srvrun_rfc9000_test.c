#include "test.h"

/* RFC 9000 / RFC 9001 rows pinned on the server's shipping path: client
 * packets sealed for real and stepped through wired_srvloop_step /
 * srvrun_serve, what the server sends read back off a loopback socket.
 * Reuses the lp_* (srvloop_test.c), sr_* (srvrun_test.c), srvrec_*
 * (srvrun_rec_test.c) and rfcpin_* (srvrun_test.c) fixtures. */

/* One client packet at pn carrying a whole POST on stream_id with the
 * one-byte body b, HEADERS and DATA+FIN coalesced, stepped through the
 * loop. */
static void rfc9000_post(struct lp_fix* f, u64 pn, u64 stream_id, u8 b) {
  u8         h[256], d[256], pl[512], spkt[1024], out[1024];
  usz        hl, dl, slen;
  wired_obuf ob = {out, sizeof out, 0};
  lp_split_post_frames_on(stream_id, &b, 1, h, sizeof h, &hl, d, sizeof d, &dl);
  bytes_memcpy(pl, h, hl);
  bytes_memcpy(pl + hl, d, dl);
  slen = client_seal_onertt_pn(f, pn, pl, hl + dl, spkt, sizeof spkt);
  wired_srvloop_step(
      &(wired_srvloop_conn){&f->l, &f->s}, wired_mspan_of(spkt, slen), &ob);
}

/* 1 if this step completed exactly one request, on stream_id, body b. */
static int rfc9000_done_one(const struct lp_fix* f, u64 stream_id, u8 b) {
  const wired_srvloop_stream_slot* s = &f->l.streams[f->l.done_slots[0]];
  return f->l.done_n == 1 && s->stream_id == stream_id &&
         s->req.body_len == 1 && s->req.body[0] == b;
}

/* RFC 9000 2.1: request streams used out of order -- stream 8 completes
 * (and is released) first, then the lower ids 4 and 0 arrive late; each
 * still opens and completes its own request, none is taken for a closed
 * stream. */
static void test_srvloop_rfc9000_late_lower_request_ids_open(void) {
  struct lp_fix f;
  u8            out[1024];
  wired_obuf    ob = {out, sizeof out, 0};
  lp_confirm(&f, &ob);
  rfc9000_post(&f, 3, 8, 'C');
  CHECK(rfc9000_done_one(&f, 8, 'C'));
  wired_srvloop_slot_release(&f.l, 8);
  rfc9000_post(&f, 4, 4, 'B');
  CHECK(rfc9000_done_one(&f, 4, 'B'));
  rfc9000_post(&f, 5, 0, 'A');
  CHECK(rfc9000_done_one(&f, 0, 'A'));
}

/* RFC 9000 3.2: the receive side enters Size Known on the FIN even before
 * the earlier bytes arrive. The DATA+FIN frame of a POST comes first: the
 * slot knows the final size (req_fin, req_len = the frame's end) yet holds
 * no request; the HEADERS that fill the hole complete it. */
static void test_srvloop_rfc9000_size_known_before_all_data(void) {
  struct lp_fix f;
  u8            h[256], d[256], spkt[1024], out[1024];
  usz           hl, dl, slen;
  wired_obuf    ob = {out, sizeof out, 0};
  stream_frame  sf;
  int           i;
  lp_split_post_frames_on(
      0, (const u8*)"hello", 5, h, sizeof h, &hl, d, sizeof d, &dl);
  CHECK(frame_get_stream(d, dl, &sf) > 0 && sf.fin);
  lp_confirm(&f, &ob);
  slen = client_seal_onertt_pn(&f, 3, d, dl, spkt, sizeof spkt);
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, wired_mspan_of(spkt, slen), &ob);
  i = srvloop_stream_slot_find(&f.l, 0);
  CHECK(i >= 0);
  CHECK(f.l.streams[i].req_fin == 1);
  CHECK(f.l.streams[i].req_len == sf.offset + sf.length);
  CHECK(f.l.streams[i].req_done == 0 && f.l.done_n == 0);
  slen = client_seal_onertt_pn(&f, 4, h, hl, spkt, sizeof spkt);
  wired_srvloop_step(
      &(wired_srvloop_conn){&f.l, &f.s}, wired_mspan_of(spkt, slen), &ob);
  CHECK(f.l.done_n == 1);
  CHECK(f.l.streams[f.l.done_slots[0]].req.body_len == 5);
}

/* The next datagram on fd opened as 1-RTT: its frame kinds, *sf its
 * leading STREAM frame (if any). */
static u32 rfc9000_rx(struct lp_fix* f, i64 fd, stream_frame* sf) {
  u8        pkt[PMTU_MAX];
  const u8* pl;
  usz       pll, n = rfcpin_recv(fd, pkt);
  CHECK(n != 0);
  CHECK(client_open_onertt(f, pkt, n, &pl, &pll) == 1);
  *sf = (stream_frame){0};
  (void)frame_get_stream(pl, pll, sf);
  return framewalk_kinds(wired_span_of(pl, pll));
}

/* RFC 9000 13.3: a lost packet is not retransmitted as is. The first send
 * of a 500-byte response carries the owed ACK beside its STREAM frame; it
 * is declared lost (three later MAX_DATA packets acknowledged) and the
 * retransmission is a new packet with the same stream bytes (offset 0, 500
 * bytes) and neither that ACK nor any PADDING. */
static void test_srvrun_rfc9000_retransmit_sends_new_frames(void) {
  static u8     body[500];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  sr_net        n;
  stream_frame  sf;
  u32           k;
  u64           r[1][2];
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  sr_net_open(&n, &c);
  pnspaces_on_recv(&c.l.ack_recv, PNS_APP, 40);
  ackpolicy_on_eliciting(&c.l.app_ack_policy, 0);
  c.l.ackst.ack_defer = 1;
  rfcpin_pump(&c, n.sfd, 0);
  k = rfc9000_rx(&f, n.afd, &sf);
  CHECK(k & (1u << FK_ACK));
  CHECK(k & (1u << FK_STREAM));
  r[0][0] = srvrec_ctrl(&c, 0);
  (void)srvrec_ctrl(&c, 0);
  r[0][1] = srvrec_ctrl(&c, 0);
  srvrec_ack_n(&c, r, 1, 0, 0);
  CHECK(c.resp[0].sess.requeue_n == 1);
  rfcpin_pump(&c, n.sfd, 1);
  k = rfc9000_rx(&f, n.afd, &sf);
  CHECK(k == 1u << FK_STREAM);
  CHECK(sf.offset == 0 && sf.length == sizeof body);
  sr_net_close(&n);
}

/* RFC 9000 18.1: transport parameter ids of the form 31 * N + 27 are
 * reserved and ignored. A ClientHello whose parameters also carry id 27
 * (N = 0, empty) and id 31027 (N = 1000, three bytes) passes the server's
 * ClientHello checks into the handshake flight, and the real parameters
 * beside them are still read. */
static void test_srvloop_rfc9000_reserved_tp_ignored(void) {
  static const u8 rsv[] = {0x1b, 0x00, 0x80, 0x00, 0x79, 0x33, 0x03, 1, 2, 3};
  struct lp_fix   f;
  u8              tp[64], cli_pub[32];
  usz             n;
  lp_make_client_hello_no_modes(&f);
  n = lp_client_tp(tp, sizeof tp);
  bytes_memcpy(tp + n, rsv, sizeof rsv);
  n += sizeof rsv;
  wired_x25519_base(cli_pub, f.cli_priv);
  f.ch_len = tls_client_hello(
      &(clienthello_in){
          f.srv_random, cli_pub, wired_span_of(0, 0), wired_span_of(tp, n)},
      &(wired_obuf){f.ch, sizeof(f.ch), 0});
  lp_drive_to_flight(&f); /* CHECKs the ClientHello was accepted */
  CHECK(f.s.sdrv.peer_initial_max_data == 1u << 24);
  CHECK(f.s.sdrv.peer_initial_max_streams_uni == 100);
}

/* 1 if no packet coalesced in datagram pkt[0..n) is an Initial (RFC 9000
 * 17.2: long header, type 0); a short header packet runs to the end
 * (RFC 9000 12.2). */
static int rfc9000_no_initial(const u8* pkt, usz n) {
  usz off = 0;
  while (off < n && (pkt[off] & 0x80)) {
    lhdr h;
    if ((pkt[off] & 0x30) == 0) {
      return 0;
    }
    CHECK(lhdr_parse(wired_span_of(pkt + off, n - off), 0, &h) == 1);
    off += h.pn_off + (usz)h.length;
  }
  return 1;
}

/* RFC 9001 4.9.1 (9001-025): the server discards its Initial keys when it
 * first processes a client Handshake packet (a real one, through
 * srvrun_serve). After that a valid client Initial -- an ACK of the
 * ServerHello -- is neither processed (the ServerHello stays
 * unacknowledged) nor answered, and the boot PTO sends no Initial. */
static void test_srvrun_rfc9001_no_initial_after_handshake(void) {
  srvrec_bootfix bf;
  sr_net         n;
  u8             dg[PMTU_MAX];
  usz            len;
  int            sent = 0;
  srvrec_boot(&bf, 3 * 1220, 0, 0);
  bf.c->boot_rx_bytes = 100000;
  sr_net_open(&n, bf.c);
  bf.peer = n.a;
  srvrun_serve(&bf.ctx, wired_mspan_of(dg, sr_client_hs_ping(bf.c, 0, dg)));
  CHECK(bf.c->l.hs_rx_seen == 1);
  while (rfcpin_recv(n.afd, dg)) {
  }
  srvrun_serve(&bf.ctx, wired_mspan_of(dg, srvrec_client_ini_ack(bf.c, dg)));
  CHECK(bf.c->boot_ini_acked == 0);
  CHECK(rfcpin_recv(n.afd, dg) == 0);
  bf.ctx.now_ms = 10 * SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_boot_pto_slot(&bf.ctx, 0);
  while ((len = rfcpin_recv(n.afd, dg)) != 0) {
    CHECK(rfc9000_no_initial(dg, len));
    sent++;
  }
  CHECK(sent >= 1); /* the PTO did probe, in Handshake packets */
  sr_net_close(&n);
}

/* RFC 9001 7 (9001-076): Initial packets are not authenticated -- anyone
 * who saw the client's first Initial can derive their keys (RFC 9001 5.2)
 * -- so once a client Handshake packet proved the peer, what a later Initial
 * carries is not acted on. Here: CRYPTO data past the ClientHello, which
 * closes the connection with PROTOCOL_VIOLATION while the Initial keys are
 * still in use (RFC 9001 4.1.3), is ignored after a client Handshake packet
 * was processed -- the connection stays up and open. */
static void test_srvrun_rfc9001_unauth_initial_not_acted_on(void) {
  srvrec_bootfix bf;
  u8             dg[PMTU_MAX];
  int            is_app = -1;
  for (int hs = 1; hs >= 0; hs--) {
    srvrec_boot(&bf, 3 * 1220, 0, 0);
    bf.c->boot_rx_bytes = 100000;
    if (hs) {
      srvrun_serve(&bf.ctx, wired_mspan_of(dg, sr_client_hs_ping(bf.c, 0, dg)));
      CHECK(bf.c->l.hs_rx_seen == 1);
    }
    srvrun_serve(
        &bf.ctx,
        wired_mspan_of(
            dg, srvrec_client_ini_crypto(bf.c, bf.c->s.ini_rx_end, dg)));
    CHECK(bf.c->up == 1);
    CHECK(bf.c->closing == !hs);
  }
  CHECK(sr_close_code(bf.c, &is_app) == ERR_PROTOCOL_VIOLATION);
}

void test_srvrun_rfc9000(void) {
  test_srvloop_rfc9000_late_lower_request_ids_open();
  test_srvloop_rfc9000_size_known_before_all_data();
  test_srvrun_rfc9000_retransmit_sends_new_frames();
  test_srvloop_rfc9000_reserved_tp_ignored();
  test_srvrun_rfc9001_no_initial_after_handshake();
  test_srvrun_rfc9001_unauth_initial_not_acted_on();
}
