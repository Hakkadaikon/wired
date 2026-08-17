#include "transport/conn/loop/connrunner/pmtudrive.h"

#include "test.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/recovery/detect/recovery/rtt.h"

static const u8 g_pd_dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

/* Same construction as connrunner_test's mk_runner: lift the gates so a send
 * actually seals. */
static void pd_mk_runner(quic_connrunner* r) {
  quic_sockaddr           peer = {0};
  quic_connrunner_init_in in   = {
      -1, &peer, QUIC_LEVEL_INITIAL, 1u << 20, 64, 1, 0xc3, 1u << 20};
  quic_connrunner_init(r, wired_span_of(g_pd_dcid, 8), &in);
  r->io.loop.validated   = 1;
  r->loop.gate.validated = 1;
  keyset_install(&r->io.loop.keys, QUIC_LEVEL_INITIAL, &(initial_keys){0});
  keyset_install(&r->loop.gate.keys, QUIC_LEVEL_INITIAL, &(initial_keys){0});
}

/* RFC 8899 3.2/5: the first probe is PING + PADDING sized to the first
 * candidate (base + step), sealed as a real packet. */
static void test_pmtudrive_build_probe_ping_plus_padding(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob  = obuf_of(pkt, sizeof(pkt));
  usz        out = quic_connrunner_pmtu_build_probe(&r, &ob, 0);
  CHECK(out != 0);
  CHECK(r.pmtu.probe == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(r.pmtu_probe_held == 1);
}

/* RFC 8899 3.4/5: the probe's plaintext content is PING followed only by
 * PADDING, never a frame carrying retransmittable user data (STREAM etc). */
static void test_pmtudrive_probe_frame_is_ping_plus_padding_only(void) {
  u8  buf[64];
  usz n = build_ping_padding(buf, sizeof(buf), 32);
  CHECK(n == 32);
  CHECK(buf[0] == QUIC_FRAME_PING);
  for (usz i = 1; i < n; i++) CHECK(buf[i] == QUIC_FRAME_PADDING);
}

/* Only one probe outstanding at a time (RFC 8899 5.1.3 PROBED_SIZE): a
 * second build while one is unresolved does nothing. */
static void test_pmtudrive_build_probe_single_outstanding(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob1 = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob1, 0) != 0);
  wired_obuf ob2 = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob2, 0) == 0);
}

/* RFC 8899 3.3: an ack of the outstanding probe's pn raises validated/MPS and
 * clears the outstanding flag so the next build proceeds. */
static void test_pmtudrive_on_ack_confirms_matching_pn(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 0) != 0);
  u64 pn = r.pmtu_probe_pn;

  quic_connrunner_pmtu_on_ack(&r, pn);
  CHECK(r.pmtu.validated == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(r.pmtu_probe_held == 0);
}

/* An ack of some other pn (not the outstanding probe) is a no-op. */
static void test_pmtudrive_on_ack_ignores_other_pn(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 0) != 0);

  quic_connrunner_pmtu_on_ack(&r, r.pmtu_probe_pn + 1);
  CHECK(r.pmtu.validated == QUIC_PMTU_BASE); /* unchanged */
  CHECK(r.pmtu_probe_held == 1);             /* still outstanding */
}

/* RFC 8899 3.4/5.1.2: a loss of the outstanding probe's pn is fed to
 * quic_pmtu_on_loss and clears the outstanding flag. */
static void test_pmtudrive_on_loss_matches_pn(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 0) != 0);
  u64 pn = r.pmtu_probe_pn;

  quic_connrunner_pmtu_on_loss(&r, pn);
  CHECK(r.pmtu.ceiling == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(r.pmtu_probe_held == 0);
}

/* RFC 9002 6.1: a probe must be recorded in the sentmeta ring like any other
 * sent packet, or loss detection (packet threshold) can never see it. */
static void test_pmtudrive_track_sent_registers_in_sentmeta(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob  = obuf_of(pkt, sizeof(pkt));
  usz        out = quic_connrunner_pmtu_build_probe(&r, &ob, 0);
  CHECK(out != 0);

  quic_connrunner_pmtu_track_sent(&r, 1, out);
  CHECK(quic_sentmeta_find(&r.sent, r.pmtu_probe_pn) != QUIC_SENTMETA_CAP);
}

/* No probe outstanding (or a zero-length send): track_sent is a no-op, never
 * registering a bogus pn 0 entry. */
static void test_pmtudrive_track_sent_noop_without_probe(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  quic_connrunner_pmtu_track_sent(&r, 1, 64);
  CHECK(quic_sentmeta_find(&r.sent, 0) == QUIC_SENTMETA_CAP);
}

/* RFC 8899 3.3: reconcile recognizes the outstanding probe's pn at or below
 * this round's largest_acked as delivered. */
static void test_pmtudrive_reconcile_acks(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 0) != 0);
  r.io.disp.has_ack       = 1;
  r.io.disp.largest_acked = r.pmtu_probe_pn;

  quic_connrunner_pmtu_reconcile(&r, (const u64*)0, 0, 0);
  CHECK(r.pmtu.validated == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(r.pmtu_probe_held == 0);
}

/* RFC 8899 3.4: reconcile recognizes the outstanding probe's pn inside the
 * lost set as lost, bounding the ceiling. */
static void test_pmtudrive_reconcile_losses(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 0) != 0);
  u64 lost[1] = {r.pmtu_probe_pn};

  quic_connrunner_pmtu_reconcile(&r, lost, 1, 0);
  CHECK(r.pmtu.ceiling == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(r.pmtu_probe_held == 0);
}

/* Neither acked nor in the lost set: reconcile leaves the probe outstanding.
 */
static void test_pmtudrive_reconcile_leaves_unresolved_outstanding(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 0) != 0);

  quic_connrunner_pmtu_reconcile(&r, (const u64*)0, 0, 0);
  CHECK(r.pmtu_probe_held == 1);
}

/* RFC 8899 5.1.1: reconcile treats an outstanding probe as lost once the
 * PROBE_TIMER has expired unacked, even with no loss detection input. */
static void test_pmtudrive_reconcile_probe_timer_expiry(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 1000) != 0);

  quic_connrunner_pmtu_reconcile(
      &r, (const u64*)0, 0, 1000 + QUIC_PMTU_PROBE_TIMER_US);
  CHECK(r.pmtu.ceiling == QUIC_PMTU_BASE + QUIC_PMTU_STEP);
  CHECK(r.pmtu_probe_held == 0);
}

/* Before the PROBE_TIMER expires, reconcile leaves an unresolved probe
 * outstanding (same as test_pmtudrive_reconcile_leaves_unresolved_outstanding,
 * but pinning the boundary just under the timer). */
static void test_pmtudrive_reconcile_probe_timer_not_yet_due(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob, 1000) != 0);

  quic_connrunner_pmtu_reconcile(
      &r, (const u64*)0, 0, 1000 + QUIC_PMTU_PROBE_TIMER_US - 1);
  CHECK(r.pmtu_probe_held == 1);
}

/* RFC 8899 3.2/5.1: once the handshake is confirmed and an iteration has
 * nothing else to send, quic_connrunner_advance opportunistically sends a
 * PLPMTU probe as its own datagram, sized larger than send_len. */
static void test_pmtudrive_advance_sends_probe_when_idle(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  r.loop.gate.handshake_confirmed = 1;

  usz out = quic_connrunner_advance(&r, 0, wired_mspan_of((u8*)0, 0));
  CHECK(out > r.loop.send_len); /* strictly larger than a normal packet */
  CHECK(r.pmtu_probe_held == 1);
  CHECK(quic_sentmeta_find(&r.sent, r.pmtu_probe_pn) != QUIC_SENTMETA_CAP);
}

/* Before the handshake is confirmed, advance never sends a probe (RFC 8899's
 * search only makes sense once the connection is otherwise idle/established).
 */
static void test_pmtudrive_advance_no_probe_before_confirm(void) {
  quic_connrunner r;
  pd_mk_runner(&r);

  usz out = quic_connrunner_advance(&r, 0, wired_mspan_of((u8*)0, 0));
  CHECK(out == 0);
  CHECK(r.pmtu_probe_held == 0);
}

/* RFC 8899 5.2: once Search Complete is reached and the PMTU_RAISE_TIMER
 * (600s) elapses, the next build_probe call resumes the search instead of
 * staying concluded forever. */
static void test_pmtudrive_build_probe_resumes_after_raise_timer(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob1   = obuf_of(pkt, sizeof(pkt));
  usz        first = quic_connrunner_pmtu_build_probe(&r, &ob1, 0);
  CHECK(first != 0);
  quic_connrunner_pmtu_on_loss(&r, r.pmtu_probe_pn); /* caps the ceiling */
  CHECK(r.pmtu.searching == 1); /* not concluded yet -- next_probe not rerun */

  /* The candidate is now above the just-capped ceiling, so this build_probe
   * call's own quic_pmtu_next_probe concludes the search (searching -> 0)
   * before the PMTU_RAISE_TIMER has had any chance to fire (now=0 still). */
  wired_obuf ob2 = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob2, 0) == 0);
  CHECK(r.pmtu.searching == 0);

  /* Once QUIC_PMTU_RAISE_TIMER_US has elapsed since that conclusion, the
   * next build_probe call resumes the search and finds a new candidate. */
  wired_obuf ob3 = obuf_of(pkt, sizeof(pkt));
  CHECK(
      quic_connrunner_pmtu_build_probe(&r, &ob3, QUIC_PMTU_RAISE_TIMER_US) !=
      0);
  CHECK(r.pmtu.searching == 1);
}

/* RFC 8899 3.7: a fresh probe must not follow the previous one by less than
 * one RTT, even though probe transmission bypasses the congestion controller.
 * Right after an ack resolves the outstanding probe, an immediate re-attempt
 * (elapsed < 1 RTT) yields no candidate. */
static void test_pmtudrive_next_probe_blocked_within_min_interval(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob1 = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob1, 1000) != 0);
  u64 pn = r.pmtu_probe_pn;

  quic_connrunner_pmtu_on_ack(&r, pn);

  wired_obuf ob2 = obuf_of(pkt, sizeof(pkt));
  usz        out = quic_connrunner_pmtu_build_probe(
      &r, &ob2, 1000 + QUIC_RTT_INITIAL_US - 1);
  CHECK(out == 0);
  CHECK(r.pmtu_probe_held == 0);
}

/* Counterpart: once at least one RTT has elapsed since the previous probe was
 * sent, the next probe is allowed. */
static void test_pmtudrive_next_probe_allowed_after_min_interval(void) {
  quic_connrunner r;
  pd_mk_runner(&r);
  u8         pkt[QUIC_PMTU_MAX + 64];
  wired_obuf ob1 = obuf_of(pkt, sizeof(pkt));
  CHECK(quic_connrunner_pmtu_build_probe(&r, &ob1, 1000) != 0);
  u64 pn = r.pmtu_probe_pn;

  quic_connrunner_pmtu_on_ack(&r, pn);

  wired_obuf ob2 = obuf_of(pkt, sizeof(pkt));
  usz        out =
      quic_connrunner_pmtu_build_probe(&r, &ob2, 1000 + QUIC_RTT_INITIAL_US);
  CHECK(out != 0);
  CHECK(r.pmtu_probe_held == 1);
}

void test_pmtudrive(void) {
  test_pmtudrive_build_probe_ping_plus_padding();
  test_pmtudrive_probe_frame_is_ping_plus_padding_only();
  test_pmtudrive_build_probe_single_outstanding();
  test_pmtudrive_on_ack_confirms_matching_pn();
  test_pmtudrive_on_ack_ignores_other_pn();
  test_pmtudrive_on_loss_matches_pn();
  test_pmtudrive_track_sent_registers_in_sentmeta();
  test_pmtudrive_track_sent_noop_without_probe();
  test_pmtudrive_reconcile_acks();
  test_pmtudrive_reconcile_losses();
  test_pmtudrive_reconcile_leaves_unresolved_outstanding();
  test_pmtudrive_reconcile_probe_timer_expiry();
  test_pmtudrive_reconcile_probe_timer_not_yet_due();
  test_pmtudrive_advance_sends_probe_when_idle();
  test_pmtudrive_advance_no_probe_before_confirm();
  test_pmtudrive_build_probe_resumes_after_raise_timer();
  test_pmtudrive_next_probe_blocked_within_min_interval();
  test_pmtudrive_next_probe_allowed_after_min_interval();
}
