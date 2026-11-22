#include "test.h"

/* RFC 8899 rows pinned on the server loop: the DPLPMTUD probe
 * srvrun_pump_sess sends, read back off a loopback socket and opened as the
 * client would (srvrun_test.c's rfcpin_* helpers, same translation
 * unit). */

/* A confirmed connection whose search starts now (srvrun_pmtu_start), its
 * sends on n's loopback sockets, nothing armed; the first pump pass at 0
 * sends the first probe. */
static void rfc8899_probe_conn(
    srvrun_conn* c, struct lp_fix* f, wired_obuf* ob, sr_net* n) {
  srvrec_bare(c, f, ob);
  sr_net_open(n, c);
  srvrun_pmtu_start(c);
  rfcpin_pump(c, n->sfd, 0);
  CHECK(srvrun_pmtu_probe_outstanding(c));
}

/* RFC 8899 3.4 (8899-005): the probe the server loop sends opens as one
 * 1-RTT packet whose frames are a PING and then PADDING to the end -- no
 * data that would need retransmitting. Its plaintext is sized for the
 * worst-case 20-byte DCID and 4-byte packet number (srvrun_pmtu_probe_len),
 * so the datagram is (20 - DCID length) + (4 - packet number length) bytes
 * under the probed size: pinned exactly, so that gap stays visible. */
static void test_srvrun_rfc8899_probe_is_ping_padding(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024], pkt[PMTU_MAX];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  sr_net        n;
  const u8*     pl;
  usz           pll, len;
  rfc8899_probe_conn(&c, &f, &ob, &n);
  len = rfcpin_recv(n.afd, pkt);
  CHECK(client_open_onertt(&f, pkt, len, &pl, &pll) == 1);
  /* header protection is removed in place: byte 0 holds the pn length */
  CHECK(
      len == c.pmtu_probe_size - (20 - c.l.cli_scid_len) -
                 (4 - ((pkt[0] & 0x03) + 1u)));
  CHECK(len > PMTU_BASE);
  CHECK(
      framewalk_kinds(wired_span_of(pl, pll)) ==
      ((1u << FK_PING) | (1u << FK_PADDING)));
  CHECK(pl[0] == FRAME_PING);
  for (usz i = 1; i < pll; i++) {
    CHECK(pl[i] == FRAME_PADDING);
  }
  CHECK(rfcpin_recv(n.afd, pkt) == 0);
  sr_net_close(&n);
}

/* RFC 8899 3.7 (8899-007): the probe is lost (three later MAX_DATA packets
 * acknowledged, RFC 9002 6.1.1) and the next send opportunity resolves the
 * loss into the search (PROBE_COUNT 1) -- the congestion window, ssthresh
 * and recovery state stay as they were. */
static void test_srvrun_rfc8899_lost_probe_keeps_cwnd(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  sr_net        n;
  u64           cwnd, ssthresh, p0, r[1][2];
  rfc8899_probe_conn(&c, &f, &ob, &n);
  cwnd     = c.cc.cwnd;
  ssthresh = c.cc.ssthresh;
  p0       = srvrec_ctrl(&c, 1);
  (void)srvrec_ctrl(&c, 1);
  r[0][1] = srvrec_ctrl(&c, 1);
  r[0][0] = p0;
  srvrec_ack_n(&c, r, 1, 0, 2);
  rfcpin_pump(&c, n.sfd, 2);
  CHECK(c.pmtu.probe_count == 1);
  CHECK(c.cc.cwnd == cwnd);
  CHECK(c.cc.ssthresh == ssthresh);
  CHECK(c.cc.in_recovery == 0);
  sr_net_close(&n);
}

/* RFC 8899 3.8 (8899-009): the probe takes no flow-control credit -- it
 * goes out with the connection credit exhausted (conn_credit 0), and the
 * connection's consumed stream bytes and credit are unchanged after it. */
static void test_srvrun_rfc8899_probe_takes_no_credit(void) {
  struct lp_fix f;
  srvrun_conn   c;
  u8            obuf[1024];
  wired_obuf    ob = {obuf, sizeof obuf, 0};
  sr_net        n;
  srvrec_bare(&c, &f, &ob);
  sr_net_open(&n, &c);
  srvrun_pmtu_start(&c);
  c.conn_credit = 0;
  rfcpin_pump(&c, n.sfd, 0);
  CHECK(srvrun_pmtu_probe_outstanding(&c));
  CHECK(c.conn_credit == 0);
  CHECK(srvrun_conn_consumed_bytes(&c) == 0);
  CHECK(rfcpin_kinds(&f, n.afd) & (1u << FK_PING));
  sr_net_close(&n);
}

void test_srvrun_rfc8899(void) {
  test_srvrun_rfc8899_probe_is_ping_padding();
  test_srvrun_rfc8899_lost_probe_keeps_cwnd();
  test_srvrun_rfc8899_probe_takes_no_credit();
}
