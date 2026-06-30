#ifndef QUIC_CONNRUNNER_RECV_H
#define QUIC_CONNRUNNER_RECV_H

#include "transport/conn/loop/connrunner/connrunner.h"

/* RFC 9000 12.2 / RFC 9001 5: turn one received UDP datagram into loop input.
 * Split it into coalesced packets, decide each packet's level, open and
 * dispatch it through connio, and queue an ack-eliciting receive into the loop
 * for any packet that elicited one. dgram is modified in place (AEAD). */

/* Process one received datagram. Returns the number of packets accepted. */
usz quic_connrunner_process_datagram(quic_connrunner *r, u8 *dgram, usz len);

/* RFC 9002 A.2.2: if the last received datagram carried an ACK, reconcile the
 * sentmeta ring against its Largest Acknowledged -- every tracked packet at or
 * below it is acknowledged, dropping its bytes from in-flight. */
void quic_connrunner_track_acks(quic_connrunner *r);

#endif
