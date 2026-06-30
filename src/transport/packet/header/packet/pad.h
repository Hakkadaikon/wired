#ifndef QUIC_PACKET_PAD_H
#define QUIC_PACKET_PAD_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.1: a datagram containing an Initial packet must be at least
 * 1200 bytes; a client pads to that minimum. */

#define QUIC_MIN_INITIAL_DATAGRAM 1200

/* PADDING bytes needed to bring a datagram of cur_len up to the 1200-byte
 * minimum (0 if it is already large enough). */
usz quic_pad_needed(usz cur_len);

#endif
