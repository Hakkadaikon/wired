#ifndef QUIC_CONNRUNNER_PMTUDRIVE_H
#define QUIC_CONNRUNNER_PMTUDRIVE_H

#include "transport/conn/cid/pmtu/pmtu.h"
#include "transport/conn/loop/connrunner/connrunner.h"

/* RFC 8899 (DPLPMTUD) via RFC 9000 14.3: drive the quic_pmtu search state
 * machine over the connrunner's real send/ack/loss path. A probe is a PING
 * frame padded with PADDING to the candidate size (RFC 8899 3.2/5), sealed
 * and sent like any other packet; the sentmeta ring's pn/size bookkeeping
 * (already used for RFC 9002 loss detection) tells this layer whether the
 * probe now outstanding was acknowledged or lost, without a second tracking
 * structure. */

/* Reset the search to the base PLPMTU and clear any outstanding probe. */
void quic_connrunner_pmtu_init(quic_connrunner* r);

/* RFC 8899 3.2/5.1: build one probe packet -- a PING frame followed by
 * PADDING out to the next candidate size (quic_pmtu_next_probe) -- and seal
 * it via connio at the current level. Returns the sealed datagram length
 * into out, or 0 if the search is done, a probe is already outstanding, or
 * the candidate does not fit `out`. Records the packet number the probe was
 * sent under so the ack/loss paths can recognize it. */
usz quic_connrunner_pmtu_build_probe(quic_connrunner* r, quic_obuf* out);

/* RFC 8899 3.3: if `pn` is the outstanding probe's packet number, tell the
 * search it was delivered (raises validated/MPS, resets PROBE_COUNT). */
void quic_connrunner_pmtu_on_ack(quic_connrunner* r, u64 pn);

/* RFC 8899 3.4/5.1.2/4.3: if `pn` is the outstanding probe's packet number,
 * tell the search it was lost (increments PROBE_COUNT; MAX_PROBES losses
 * bound the ceiling, or -- at the validated size -- drop the PLPMTU back to
 * base, RFC 8899 4.3 black hole detection). */
void quic_connrunner_pmtu_on_loss(quic_connrunner* r, u64 pn);

/* RFC 9002 6.1: an outstanding probe only participates in loss detection once
 * it is recorded in the sentmeta ring like any other sent packet -- call once
 * per build_probe success, mirroring quic_connrunner_track_sent. */
void quic_connrunner_pmtu_track_sent(quic_connrunner* r, u64 now, usz len);

/* RFC 8899 3.3/3.4: after quic_connrunner_track_acks/track_loss have run for
 * this iteration, reconcile the outstanding probe against what they found --
 * acked if its pn is at or below the just-processed largest_acked, lost if it
 * appears in `lost[0..n)` (the array quic_connrunner_track_loss's detection
 * pass produced this round). */
void quic_connrunner_pmtu_reconcile(quic_connrunner* r, const u64* lost, usz n);

#endif
