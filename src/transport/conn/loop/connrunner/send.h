#ifndef CONNRUNNER_SEND_H
#define CONNRUNNER_SEND_H

#include "transport/conn/loop/connrunner/connrunner.h"

/* RFC 9000 12.1 / RFC 9001 5: turn the loop's send decision into a sealed
 * datagram. The loop has already applied every gate (cwnd, anti-amp, phase) and
 * advanced next_pn iff it chose to send; this layer only builds the frame the
 * loop would have sent -- an owed ACK first, else a retransmission, else new
 * data, matching the loop's own priority -- seals it via connio, and sends it.
 */

/* The frame kind the loop would send next, given its pre-step state: 0 none,
 * 1 ACK, 2 retransmission, 3 new data. Priority matches phase_send. Capture
 * this BEFORE evloop_step, which clears ack_owed / drains the queues. */
int connrunner_pending_kind(const connrunner* r);

/* RFC 9002 13.3: capture the oldest queued lost pn BEFORE evloop_step
 * consumes it, so the flush can resend that packet's real bytes. */
void connrunner_capture_rtx(connrunner* r);

/* Flush the send the loop just decided. `sent_before` is next_pn captured right
 * before evloop_step and `kind` the pending kind captured then too; if
 * next_pn advanced, that kind's packet is built and sealed into r->txbuf.
 * Returns the sealed datagram length, or 0 if nothing was sent. */
usz connrunner_flush_sends(connrunner* r, u64 sent_before, int kind);

/** Everything connrunner_track_sent needs besides the runner. */
typedef struct {
  u64 now;
  int kind;
  usz sent_len;
} connrunner_sent_in;

/* RFC 9002 A.1 OnPacketSent: record the just-sealed packet's metadata into the
 * sentmeta ring. `sent_len` is the sealed datagram length (0 = nothing sent);
 * `kind` (1 ACK / 2 rtx / 3 new data) decides ack-eliciting and in-flight: an
 * ACK-only packet is neither, a retransmission or new data is both. The packet
 * number is the send level space's next-1 (connio advanced it on the send). */
void connrunner_track_sent(connrunner* r, const connrunner_sent_in* in);

/* RFC 9002 6.1: run real loss detection over the sentmeta ring at `now` and,
 * if the loop captured no lost pn for this send, feed the oldest sentmeta-lost
 * pn into rtx_pn/rtx_held so flush_sends resends its real bytes. */
void connrunner_track_loss(connrunner* r, u64 now);

/* Same detection pass as connrunner_track_loss, but also returns the
 * full lost-pn set into lost[0..*n) (capacity SENTMETA_CAP) for a caller
 * that needs to recognize a specific pn among them (e.g. RFC 8899 DPLPMTUD's
 * outstanding probe) rather than just the oldest one. */
void connrunner_track_loss_ex(connrunner* r, u64 now, u64* lost, usz* n);

#endif
