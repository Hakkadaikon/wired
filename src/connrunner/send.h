#ifndef QUIC_CONNRUNNER_SEND_H
#define QUIC_CONNRUNNER_SEND_H

#include "connrunner/connrunner.h"

/* RFC 9000 12.1 / RFC 9001 5: turn the loop's send decision into a sealed
 * datagram. The loop has already applied every gate (cwnd, anti-amp, phase) and
 * advanced next_pn iff it chose to send; this layer only builds the frame the
 * loop would have sent -- an owed ACK first, else a retransmission, else new
 * data, matching the loop's own priority -- seals it via connio, and sends it. */

/* The frame kind the loop would send next, given its pre-step state: 0 none,
 * 1 ACK, 2 retransmission, 3 new data. Priority matches phase_send. Capture
 * this BEFORE quic_evloop_step, which clears ack_owed / drains the queues. */
int quic_connrunner_pending_kind(const quic_connrunner *r);

/* RFC 9002 13.3: capture the oldest queued lost pn BEFORE quic_evloop_step
 * consumes it, so the flush can resend that packet's real bytes. */
void quic_connrunner_capture_rtx(quic_connrunner *r);

/* Flush the send the loop just decided. `sent_before` is next_pn captured right
 * before quic_evloop_step and `kind` the pending kind captured then too; if
 * next_pn advanced, that kind's packet is built and sealed into r->txbuf.
 * Returns the sealed datagram length, or 0 if nothing was sent. */
usz quic_connrunner_flush_sends(quic_connrunner *r, u64 sent_before, int kind);

#endif
