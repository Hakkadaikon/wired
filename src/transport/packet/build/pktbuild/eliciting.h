#ifndef QUIC_PKTBUILD_ELICITING_H
#define QUIC_PKTBUILD_ELICITING_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 13.2.1: a packet is ack-eliciting if it contains any frame other
 * than ACK, PADDING, or CONNECTION_CLOSE. Given the n frame types in a packet,
 * returns 1 if the packet is ack-eliciting, 0 otherwise. */
int quic_pktbuild_is_eliciting(const u8 *frame_types, usz n);

#endif
