#include "transport/conn/loop/connrunner/pmtudrive.h"

#include "common/bytes/util/bytes.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/recovery/detect/recovery/rtt.h"
#include "transport/recovery/rtx/sentmeta/record.h"

void connrunner_pmtu_init(connrunner* r) {
  pmtu_init(&r->pmtu);
  r->pmtu_probe_pn   = 0;
  r->pmtu_probe_held = 0;
  /* RFC 8899 3.7: pushed QUIC_RTT_INITIAL_US into the past (wrapping is fine
   * -- u64 arithmetic) so the very first probe, whatever `now` is, is never
   * held back by the min-interval gate below. */
  r->pmtu_last_probe_sent_at = (u64)0 - QUIC_RTT_INITIAL_US;
}

/* RFC 8899 3.2/5: a PING frame (1 byte, ack-eliciting) followed by PADDING
 * (0x00) frames filling the rest -- carries no application data that would
 * need retransmission if the probe is lost (RFC 8899 3.4). Returns size, or
 * 0 if size does not fit cap. */
static usz build_ping_padding(u8* buf, usz cap, usz size) {
  if (size == 0 || size > cap) return 0;
  buf[0] = QUIC_FRAME_PING;
  bytes_memset(buf + 1, QUIC_FRAME_PADDING, size - 1);
  return size;
}

/* RFC 8899 3.7: probe transmission bypasses the congestion controller, so
 * this is the only pacing a probe gets -- at least one RTT must separate a
 * new probe send from the previous one. No live RTT sample is wired into
 * this loop yet (send.c: QUIC_CONNRUNNER_NO_RTT_DELAY), so
 * QUIC_RTT_INITIAL_US (RFC 9002's own kInitialRtt floor) stands in as the
 * minimum interval. Only gates an actual send, not the search state machine
 * itself (pmtu_next_probe still runs to conclude a finished search). */
static int within_min_probe_interval(const connrunner* r, u64 now) {
  return now - r->pmtu_last_probe_sent_at < QUIC_RTT_INITIAL_US;
}

/* A found candidate is held back if it would violate the min interval above;
 * 0 (search concluded/no candidate) passes through unchanged either way. A
 * held-back candidate leaves pmtu's own probe/probe_sent_at set, but
 * that is inert here: every connrunner consumer of them is gated on
 * pmtu_probe_held, which stays 0 until a probe is actually sealed (below),
 * and the next call recomputes the candidate fresh from validated/ceiling. */
static usz gate_min_interval(const connrunner* r, u64 now, usz size) {
  if (!size) return 0;
  return within_min_probe_interval(r, now) ? 0 : size;
}

/* The next candidate size to probe, or 0 if none: only one probe may be
 * outstanding at a time (RFC 8899 5.1.3 PROBED_SIZE is a single value), so a
 * fresh one is not started while one is still unresolved. RFC 8899 5.2: once
 * the PMTU_RAISE_TIMER fires after Search Complete, resume the search first
 * so a larger candidate becomes available again. */
static usz next_probe_size(connrunner* r, u64 now) {
  if (r->pmtu_probe_held) return 0;
  if (pmtu_raise_timer_due(&r->pmtu, now)) pmtu_resume_search(&r->pmtu);
  return gate_min_interval(r, now, pmtu_next_probe(&r->pmtu, now));
}

/* Seal a PING+PADDING frame of `fl` bytes at the loop's level, recording the
 * pn it was sent under for the ack/loss paths to recognize, and `now` as the
 * min-interval clock (RFC 8899 3.7) that survives ack/loss resolution. */
static usz seal_probe(
    connrunner* r, wired_span frame, wired_obuf* out, u64 now) {
  usz            sealed;
  connio_send_in sin = {r->loop.level, frame};
  r->pmtu_probe_pn   = connio_tx_next(&r->io, r->loop.level);
  sealed             = connio_send(&r->io, &sin, out);
  r->pmtu_probe_held = sealed != 0;
  if (sealed) r->pmtu_last_probe_sent_at = now;
  return sealed;
}

usz connrunner_pmtu_build_probe(connrunner* r, wired_obuf* out, u64 now) {
  u8  frame[QUIC_PMTU_MAX];
  usz size = next_probe_size(r, now);
  usz fl;
  if (!size) return 0;
  fl = build_ping_padding(frame, sizeof(frame), size);
  if (!fl) return 0;
  return seal_probe(r, wired_span_of(frame, fl), out, now);
}

/* pn is the outstanding probe's, and still is one (guards a stray call after
 * on_ack/on_loss already cleared it, or before any probe was ever sent). */
static int is_outstanding_probe(const connrunner* r, u64 pn) {
  return r->pmtu_probe_held && pn == r->pmtu_probe_pn;
}

void connrunner_pmtu_on_ack(connrunner* r, u64 pn) {
  if (!is_outstanding_probe(r, pn)) return;
  pmtu_on_ack(&r->pmtu, r->pmtu.probe);
  r->pmtu_probe_held = 0;
}

void connrunner_pmtu_on_loss(connrunner* r, u64 pn) {
  if (!is_outstanding_probe(r, pn)) return;
  pmtu_on_loss(&r->pmtu, r->pmtu.probe);
  r->pmtu_probe_held = 0;
}

void connrunner_pmtu_track_sent(connrunner* r, u64 now, usz len) {
  sentmeta_out pkt;
  if (!r->pmtu_probe_held || len == 0) return;
  pkt = (sentmeta_out){r->pmtu_probe_pn, now, 1, 1, len};
  sentmeta_on_sent(&r->sent, &pkt);
}

/* 1 if pn appears anywhere in lost[0..n). */
static int pn_in_lost(const u64* lost, usz n, u64 pn) {
  usz i;
  for (i = 0; i < n; i++)
    if (lost[i] == pn) return 1;
  return 0;
}

/* RFC 8899 3.3: the probe's pn falls at or below this round's largest_acked
 * (mirrors connrunner_track_acks's own single-range ACK reconciliation).
 */
static int probe_was_acked(const connrunner* r) {
  return r->io.disp.has_ack && r->pmtu_probe_pn <= r->io.disp.largest_acked;
}

/* Reconcile as lost if pn is among this round's lost pns or the RFC 8899
 * 5.1.1 PROBE_TIMER has expired unacked; a no-op if a probe was already
 * reconciled as acked above (on_ack cleared pmtu_probe_held, so
 * connrunner_pmtu_on_loss's own outstanding check discards this). */
static void reconcile_loss(
    connrunner* r, u64 pn, const u64* lost, usz n, u64 now) {
  int expired = pmtu_probe_timer_due(&r->pmtu, now);
  if (pn_in_lost(lost, n, pn) || expired) connrunner_pmtu_on_loss(r, pn);
}

void connrunner_pmtu_reconcile(connrunner* r, const u64* lost, usz n, u64 now) {
  u64 pn = r->pmtu_probe_pn;
  if (!r->pmtu_probe_held) return;
  if (probe_was_acked(r)) return connrunner_pmtu_on_ack(r, pn);
  reconcile_loss(r, pn, lost, n, now);
}
