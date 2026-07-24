#include "transport/conn/loop/connrunner/pmtudrive.h"

#include "common/bytes/util/bytes.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/recovery/rtx/sentmeta/record.h"

void quic_connrunner_pmtu_init(quic_connrunner* r) {
  quic_pmtu_init(&r->pmtu);
  r->pmtu_probe_pn   = 0;
  r->pmtu_probe_held = 0;
}

/* RFC 8899 3.2/5: a PING frame (1 byte, ack-eliciting) followed by PADDING
 * (0x00) frames filling the rest -- carries no application data that would
 * need retransmission if the probe is lost (RFC 8899 3.4). Returns size, or
 * 0 if size does not fit cap. */
static usz build_ping_padding(u8* buf, usz cap, usz size) {
  if (size == 0 || size > cap) return 0;
  buf[0] = QUIC_FRAME_PING;
  quic_memset(buf + 1, QUIC_FRAME_PADDING, size - 1);
  return size;
}

/* The next candidate size to probe, or 0 if none: only one probe may be
 * outstanding at a time (RFC 8899 5.1.3 PROBED_SIZE is a single value), so a
 * fresh one is not started while one is still unresolved. */
static usz next_probe_size(quic_connrunner* r) {
  if (r->pmtu_probe_held) return 0;
  return quic_pmtu_next_probe(&r->pmtu);
}

/* Seal a PING+PADDING frame of `fl` bytes at the loop's level, recording the
 * pn it was sent under for the ack/loss paths to recognize. */
static usz seal_probe(quic_connrunner* r, quic_span frame, quic_obuf* out) {
  usz                 sealed;
  quic_connio_send_in sin = {r->loop.level, frame};
  r->pmtu_probe_pn        = quic_connio_tx_next(&r->io, r->loop.level);
  sealed                  = quic_connio_send(&r->io, &sin, out);
  r->pmtu_probe_held      = sealed != 0;
  return sealed;
}

usz quic_connrunner_pmtu_build_probe(quic_connrunner* r, quic_obuf* out) {
  u8  frame[QUIC_PMTU_MAX];
  usz size = next_probe_size(r);
  usz fl;
  if (!size) return 0;
  fl = build_ping_padding(frame, sizeof(frame), size);
  if (!fl) return 0;
  return seal_probe(r, quic_span_of(frame, fl), out);
}

/* pn is the outstanding probe's, and still is one (guards a stray call after
 * on_ack/on_loss already cleared it, or before any probe was ever sent). */
static int is_outstanding_probe(const quic_connrunner* r, u64 pn) {
  return r->pmtu_probe_held && pn == r->pmtu_probe_pn;
}

void quic_connrunner_pmtu_on_ack(quic_connrunner* r, u64 pn) {
  if (!is_outstanding_probe(r, pn)) return;
  quic_pmtu_on_ack(&r->pmtu, r->pmtu.probe);
  r->pmtu_probe_held = 0;
}

void quic_connrunner_pmtu_on_loss(quic_connrunner* r, u64 pn) {
  if (!is_outstanding_probe(r, pn)) return;
  quic_pmtu_on_loss(&r->pmtu, r->pmtu.probe);
  r->pmtu_probe_held = 0;
}

void quic_connrunner_pmtu_track_sent(quic_connrunner* r, u64 now, usz len) {
  quic_sentmeta_out pkt;
  if (!r->pmtu_probe_held || len == 0) return;
  pkt = (quic_sentmeta_out){r->pmtu_probe_pn, now, 1, 1, len};
  quic_sentmeta_on_sent(&r->sent, &pkt);
}

/* 1 if pn appears anywhere in lost[0..n). */
static int pn_in_lost(const u64* lost, usz n, u64 pn) {
  usz i;
  for (i = 0; i < n; i++)
    if (lost[i] == pn) return 1;
  return 0;
}

/* RFC 8899 3.3: the probe's pn falls at or below this round's largest_acked
 * (mirrors quic_connrunner_track_acks's own single-range ACK reconciliation).
 */
static int probe_was_acked(const quic_connrunner* r) {
  return r->io.disp.has_ack && r->pmtu_probe_pn <= r->io.disp.largest_acked;
}

/* Reconcile as lost if pn is among this round's lost pns; a no-op if a probe
 * was already reconciled as acked above (on_ack cleared pmtu_probe_held, so
 * quic_connrunner_pmtu_on_loss's own outstanding check discards this). */
static void reconcile_loss(quic_connrunner* r, u64 pn, const u64* lost, usz n) {
  if (pn_in_lost(lost, n, pn)) quic_connrunner_pmtu_on_loss(r, pn);
}

void quic_connrunner_pmtu_reconcile(
    quic_connrunner* r, const u64* lost, usz n) {
  u64 pn = r->pmtu_probe_pn;
  if (!r->pmtu_probe_held) return;
  if (probe_was_acked(r)) return quic_connrunner_pmtu_on_ack(r, pn);
  reconcile_loss(r, pn, lost, n);
}
