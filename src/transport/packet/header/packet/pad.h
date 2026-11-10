#ifndef PACKET_PAD_H
#define PACKET_PAD_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 14.1: a datagram containing an Initial packet must be at least
 * 1200 bytes. */

#define MIN_INITIAL_DATAGRAM 1200

#endif
