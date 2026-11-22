#include "test.h"

/* RFC 9002 rows pinned on the server's shipping path (srvrun_feed_acks,
 * the poll-tick timers and the pump), with what the server sends read back
 * off a loopback socket and opened as the client would. Reuses
 * srvrun_rec_test.c's srvrec_* fixtures and srvrun_test.c's sr_net and
 * rfcpin_* capture helpers (same translation unit, included earlier in
 * tests/run.c). */

/* Drain fd: every datagram opens as 1-RTT and is ack-eliciting (RFC 9002
 * 2); how many there were. */
static int rfcpin_drain_eliciting(struct lp_fix* f, i64 fd) {
  int n = 0;
  u32 k;
  while ((k = rfcpin_kinds(f, fd)) != 0) {
    CHECK(framewalk_kinds_ack_eliciting(k));
    n++;
  }
  return n;
}

/* One PTO tick of c at now_ms, sending through fd. */
static void rfcpin_pto_tick(srvrun_conn* c, i64 fd, u64 now_ms) {
  srvrun_cfg      cfg = rfcpin_cfg(fd);
  srvrun_state    st  = {0, c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, now_ms, 0};
  srvrun_pto_slot(&ctx, 0);
}

/* RFC 9002 5.2 (9002-009): min_rtt is the smallest sample. Samples 50, 30
 * and 80 ms (MAX_DATA packets acknowledged without ACK Delay): min_rtt
 * 50 ms, then 30 ms, and stays 30 ms after the larger one. */
static void test_srvrun_rfc9002_min_rtt_tracks_smallest(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn;
  srvrec_bare(&c, &f, &ob);
  pn = srvrec_ctrl(&c, 0);
  srvrec_ack(&c, pn, pn, 50);
  CHECK(c.rtt.min_rtt == 50000);
  pn = srvrec_ctrl(&c, 100);
  srvrec_ack(&c, pn, pn, 130);
  CHECK(c.rtt.min_rtt == 30000);
  pn = srvrec_ctrl(&c, 200);
  srvrec_ack(&c, pn, pn, 280);
  CHECK(c.latest_rtt_ms == 80);
  CHECK(c.rtt.min_rtt == 30000);
}

/* RFC 9002 5.3 / 6.2.2 (9002-012, 9002-035): a connection the server just
 * opened from a client Initial has no RTT sample, smoothed_rtt = kInitialRtt
 * 333 ms and rttvar = 166.5 ms. Its 1-RTT PTO is then 333 + 4 * 166.5 +
 * max_ack_delay 25 = 1024 ms (6.2.1): a MAX_DATA packet sent at 0 is not
 * probed at 1023 ms and is at 1024 ms. */
static void test_srvrun_rfc9002_initial_rtt_sets_first_pto(void) {
  srvrec_bootfix bf;
  struct lp_fix  f;
  srvrun_conn    c;
  u8             obuf[1024];
  wired_obuf     ob = {obuf, sizeof obuf, 0};
  srvrec_boot(&bf, 3 * 1220, 0, 0);
  CHECK(bf.c->rtt.have_sample == 0);
  CHECK(bf.c->rtt.smoothed_rtt == 333000);
  CHECK(bf.c->rtt.rttvar == 166500);
  CHECK(srvrun_pto_deadline_ms(bf.c, 0) == 1024);
  srvrec_bare(&c, &f, &ob); /* rtt_init: the same seed, no sample */
  (void)srvrec_ctrl(&c, 0);
  srvrec_pto_tick(&c, 1023);
  CHECK(c.l.ackst.pto_count == 0);
  srvrec_pto_tick(&c, 1024);
  CHECK(c.l.ackst.pto_count == 1);
}

/* RFC 9002 5.3 (9002-015): before the handshake is confirmed the server
 * does not cap the peer's ACK Delay at max_ack_delay. First sample 50 ms;
 * then a 100 ms sample with ACK Delay 5000 << 3 = 40 ms (above the 25 ms
 * default): unconfirmed, adjusted = 100 - 40 = 60 ms, smoothed = (7 * 50 +
 * 60) / 8 = 51.25 ms -- capped it would be 75 ms and 53.125 ms. */
static void test_srvrun_rfc9002_preconfirm_ack_delay_uncapped(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           pn;
  srvrec_bare(&c, &f, &ob);
  pn = srvrec_ctrl(&c, 0);
  srvrec_ack(&c, pn, pn, 50);
  pn        = srvrec_ctrl(&c, 100);
  c.s.phase = WIRED_SERVER_HS_INITIAL; /* not yet confirmed */
  {
    const u64 r[1][2] = {{pn, pn}};
    srvrec_ack_n(&c, r, 1, 5000, 200);
  }
  CHECK(c.rtt.smoothed_rtt == 51250);
}

/* RFC 9002 6.2.4 (9002-041): every 1-RTT PTO probe the server sends is
 * ack-eliciting -- new data past a full window (two packets), copies of
 * the oldest slices when nothing new is left (two), and the lone PING when
 * there is no data at all. */
static void test_srvrun_rfc9002_pto_probes_ack_eliciting(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  sr_net        n;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  sr_net_open(&n, &c);
  c.resp[0].stream_credit = sizeof body;
  c.cc.cwnd               = SRVRUN_CHUNK; /* room for one slice */
  rfcpin_pump(&c, n.sfd, 0);
  CHECK(rfcpin_drain_eliciting(&f, n.afd) == 1);
  rfcpin_pto_tick(&c, n.sfd, srvrun_pto_deadline_ms(&c, 0));
  CHECK(c.resp[0].sess.q.cur == 3 * SRVRUN_CHUNK); /* new data */
  CHECK(rfcpin_drain_eliciting(&f, n.afd) == 2);
  sr_net_close(&n);
  srvrec_conn(&c, &f, body, 2 * SRVRUN_CHUNK, &ob);
  sr_net_open(&n, &c);
  rfcpin_pump(&c, n.sfd, 0);
  CHECK(rfcpin_drain_eliciting(&f, n.afd) == 2);
  c.cc.cwnd = 1;
  rfcpin_pto_tick(&c, n.sfd, srvrun_pto_deadline_ms(&c, 0));
  CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 4); /* copies */
  CHECK(rfcpin_drain_eliciting(&f, n.afd) == 2);
  sr_net_close(&n);
  srvrec_bare(&c, &f, &ob);
  sr_net_open(&n, &c);
  (void)srvrec_ctrl(&c, 0); /* sealed, not sent */
  rfcpin_pto_tick(&c, n.sfd, srvrun_pto_deadline_ms(&c, 0));
  CHECK(c.l.ackst.pto_count == 1);
  CHECK(rfcpin_kinds(&f, n.afd) & (1u << FK_PING));
  CHECK(rfcpin_recv(n.afd, obuf) == 0); /* one packet */
  sr_net_close(&n);
}

/* The level (LEVEL_INITIAL / LEVEL_HANDSHAKE) of the first long-header
 * packet of datagram pkt the boot connection c sent, opened under the
 * server's keys for it as the client would; *kinds its frames. -1 when it
 * does not open. */
static int rfcpin_open_boot(const srvrun_conn* c, u8* pkt, usz n, u32* kinds) {
  initial_keys        ck, sk;
  const initial_keys* k = &sk;
  aes128              hp;
  int                 is_initial = (pkt[0] & 0x30) == 0;
  wired_span          fr;
  initpkt_derive_ver(wired_span_of(g_sr_odcid, 8), VERSION_1, &ck, &sk);
  if (!is_initial) {
    CHECK(keysched_get(&c->s.sched, KS_SERVER_HS, &k) == 1);
  }
  aes128_init(&hp, k->hp);
  {
    protect_keys pk = {k, &hp, 0};
    rx_desc      d  = {wired_mspan_of(pkt, n), is_initial, 0};
    if (!rx_packet(&pk, &d, &fr)) {
      return -1;
    }
  }
  *kinds = framewalk_kinds(fr);
  return is_initial ? LEVEL_INITIAL : LEVEL_HANDSHAKE;
}

/* The one boot probe datagram on fd: its level, *kinds its frames. */
static int rfcpin_boot_probe(const srvrun_conn* c, i64 fd, u32* kinds) {
  u8  pkt[PMTU_MAX];
  usz n = rfcpin_recv(fd, pkt);
  CHECK(n != 0);
  return rfcpin_open_boot(c, pkt, n, kinds);
}

/* RFC 9002 6.2.4 (9002-041) / RFC 9001 4 (9001-002): every boot PTO probe
 * is ack-eliciting, and the CRYPTO data it retransmits goes at the level
 * it was first sent at -- the Initial probe re-sends the ServerHello in an
 * Initial packet, the Handshake probe the flight in a Handshake packet
 * (both open only under their own level's keys). With the antiamp budget
 * too small for any cached datagram the Handshake probe is a Handshake
 * PING, still ack-eliciting. */
static void test_srvrun_rfc9002_boot_probes_eliciting_at_level(void) {
  srvrec_bootfix bf;
  sr_net         n;
  u32            k = 0;
  srvrec_boot(&bf, 3 * 1220, 0, 50);
  bf.c->boot_rx_bytes = 100000;
  sr_net_open(&n, bf.c);
  bf.peer       = n.a;
  bf.ctx.now_ms = SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_boot_pto_slot(&bf.ctx, 0);
  CHECK(rfcpin_boot_probe(bf.c, n.afd, &k) == LEVEL_INITIAL);
  CHECK(k & (1u << FK_CRYPTO));
  CHECK(framewalk_kinds_ack_eliciting(k));
  CHECK(rfcpin_recv(n.afd, (u8[PMTU_MAX]){0}) == 0); /* Initial only */
  bf.ctx.now_ms = 50 + SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_boot_pto_slot(&bf.ctx, 0);
  CHECK(rfcpin_boot_probe(bf.c, n.afd, &k) == LEVEL_HANDSHAKE);
  CHECK(k & (1u << FK_CRYPTO));
  CHECK(framewalk_kinds_ack_eliciting(k));
  sr_net_close(&n);
  srvrec_boot(&bf, 181, 50, 0);
  sr_net_open(&n, bf.c);
  bf.peer       = n.a;
  bf.ctx.now_ms = SRVRUN_BOOT_RESEND_CAP_MS;
  srvrun_boot_pto_slot(&bf.ctx, 0);
  CHECK(rfcpin_boot_probe(bf.c, n.afd, &k) == LEVEL_HANDSHAKE);
  CHECK(k & (1u << FK_PING));
  CHECK(!(k & (1u << FK_CRYPTO)));
  sr_net_close(&n);
}

/* RFC 9002 7 / 2 (9002-044): the ACK-only packet the poll tick flushes
 * leaves bytes in flight as they were -- with nothing in flight, and with a
 * MAX_DATA packet in flight. */
static void test_srvrun_rfc9002_ack_only_not_in_flight(void) {
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0, 0};
  for (int with_ctrl = 0; with_ctrl < 2; with_ctrl++) {
    u64 tx, bif;
    srvrec_bare(&c, &f, &ob);
    if (with_ctrl) {
      (void)srvrec_ctrl(&c, 0);
    }
    ackpolicy_on_ack_sent(&c.l.app_ack_policy);
    pnspaces_on_recv(&c.l.ack_recv, PNS_APP, 40);
    ackpolicy_on_eliciting(&c.l.app_ack_policy, 0);
    tx         = c.l.tx_pn;
    bif        = srvrun_bytes_in_flight(&c);
    c.l.now_ms = ctx.now_ms = WIRED_SRVLOOP_MAX_ACK_DELAY_MS;
    srvrun_ack_tick_slot(&ctx, 0);
    CHECK(c.l.tx_pn == tx + 1); /* the ACK went out */
    CHECK(srvrun_bytes_in_flight(&c) == bif);
    CHECK((bif != 0) == with_ctrl);
  }
}

/* RFC 9002 7.3.3 (9002-058): in congestion avoidance an ACK of one whole
 * window grows cwnd by exactly one max datagram size: cwnd = ssthresh =
 * four slices, all four acknowledged in one ACK -> inc = 1200 * 4400 / 4400
 * = 1200 (B.5). The bytes credited are the acknowledged slices' (the
 * session log's unit). */
static void test_srvrun_rfc9002_ca_one_datagram_per_window(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  u64           w  = 4 * SRVRUN_CHUNK;
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  for (u64 pn = 100; pn < 104; pn++) {
    srvrec_log(&c, pn, 1);
  }
  c.cc.cwnd        = w;
  c.cc.ssthresh    = w;
  c.cc.app_limited = 0;
  srvrec_ack(&c, 100, 103, 10);
  CHECK(c.cc.cwnd == w + MAX_DATAGRAM);
}

/* RFC 9002 7.4 (9002-059): once a packet of the space was acknowledged,
 * the losses of packets sent after it are declared: pn 100 acknowledged
 * first, then pn 105 -- 101 and 102 (three or more below 105, 6.1.1) are
 * declared lost and requeued; 103 and 104 are not (0 ms elapsed). */
static void test_srvrun_rfc9002_losses_after_first_acked(void) {
  static u8     body[6 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  for (u64 pn = 100; pn < 106; pn++) {
    srvrec_log(&c, pn, 1);
  }
  srvrec_ack(&c, 100, 100, 1);
  CHECK(c.resp[0].sess.requeue_n == 0);
  srvrec_ack(&c, 105, 105, 1);
  CHECK(c.resp[0].sess.requeue_n == 2);
}

/* RFC 9002 A.7 on the srvrun feed path: largest_acked = max(largest_acked,
 * the ACK's largest). An ACK of 105, then a delayed one whose largest is
 * 104: largest_acked stays 105 and the older ACK declares nothing more. A
 * send session with nothing in flight (resp[1], armed, nothing sent) is
 * skipped by the loss scan and left as it was. */
static void test_srvrun_rfc9002_largest_acked_never_regresses(void) {
  static u8     body[6 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  srvrec_conn(&c, &f, body, sizeof body, &ob);
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  wired_sendsess_arm(&c.resp[1].sess, body, sizeof body, SRVRUN_CHUNK);
  for (u64 pn = 100; pn < 106; pn++) {
    srvrec_log(&c, pn, 1);
  }
  srvrec_ack(&c, 105, 105, 1);
  CHECK(c.largest_acked == 105);
  CHECK(c.resp[0].sess.requeue_n == 3); /* 100..102 */
  srvrec_ack(&c, 103, 104, 1);
  CHECK(c.largest_acked == 105);
  CHECK(c.resp[0].sess.requeue_n == 3);
  CHECK(c.resp[1].sess.requeue_n == 0);
  CHECK(c.resp[1].sess.q.cur == 0);
  CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 0);
}

/* RFC 9002 A.8 (9002-075): with no ack-eliciting packet in flight the PTO
 * is not armed -- on a fresh connection, after an ACK-only packet went out
 * (a tick far past any deadline probes nothing), and again once the one
 * MAX_DATA packet that armed it is acknowledged. */
static void test_srvrun_rfc9002_no_pto_without_eliciting(void) {
  struct lp_fix   f;
  srvrun_conn     c;
  u8              obuf[1024];
  wired_obuf      ob  = {obuf, sizeof obuf, 0};
  srvrun_cfg      cfg = srvrec_cfg();
  srvrun_state    st  = {0, &c};
  srvrun_step_ctx ctx = {&cfg, 0, &st, WIRED_SRVLOOP_MAX_ACK_DELAY_MS, 0};
  u64             tx, pn;
  srvrec_bare(&c, &f, &ob);
  CHECK(srvrun_pto_armed(&c) == 0);
  pnspaces_on_recv(&c.l.ack_recv, PNS_APP, 40);
  ackpolicy_on_eliciting(&c.l.app_ack_policy, 0);
  c.l.now_ms = ctx.now_ms;
  srvrun_ack_tick_slot(&ctx, 0);
  CHECK(c.l.app_ack_policy.pending == 0); /* the ACK-only packet went */
  CHECK(srvrun_pto_armed(&c) == 0);
  tx = c.l.tx_pn;
  srvrec_pto_tick(&c, 1000000);
  CHECK(c.l.ackst.pto_count == 0 && c.l.tx_pn == tx);
  pn = srvrec_ctrl(&c, 1000000);
  CHECK(srvrun_pto_armed(&c) == 1);
  srvrec_ack(&c, pn, pn, 1000010);
  CHECK(srvrun_pto_armed(&c) == 0);
}

void test_srvrun_rfc9002(void) {
  test_srvrun_rfc9002_min_rtt_tracks_smallest();
  test_srvrun_rfc9002_initial_rtt_sets_first_pto();
  test_srvrun_rfc9002_preconfirm_ack_delay_uncapped();
  test_srvrun_rfc9002_pto_probes_ack_eliciting();
  test_srvrun_rfc9002_boot_probes_eliciting_at_level();
  test_srvrun_rfc9002_ack_only_not_in_flight();
  test_srvrun_rfc9002_ca_one_datagram_per_window();
  test_srvrun_rfc9002_losses_after_first_acked();
  test_srvrun_rfc9002_largest_acked_never_regresses();
  test_srvrun_rfc9002_no_pto_without_eliciting();
}
