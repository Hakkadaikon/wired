#ifndef QUIC_PACKET_RESBITS_H
#define QUIC_PACKET_RESBITS_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.2 / 17.3.1: after removing header protection, the Reserved Bits
 * of the first byte must be zero. In a long header they are bits 0x0c; in a
 * short header they are bits 0x18. A non-zero value is a PROTOCOL_VIOLATION. */

#define QUIC_RESBITS_LONG  0x0c
#define QUIC_RESBITS_SHORT 0x18

/* Whether the reserved bits of an unprotected first byte are valid (zero).
 * is_long selects the long- vs short-header mask. Returns 1 if valid. */
int quic_resbits_ok(u8 byte0, int is_long);

#endif
