#ifndef PACKET_PNUM_H
#define PACKET_PNUM_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 Appendix A.2/A.3: packet number truncation and recovery.
 * Packet numbers are 62-bit and sent truncated to 1, 2, or 4 bytes. */

/* Truncate full_pn to nbytes (1/2/4) big-endian into buf.
 * Returns nbytes. */
usz pnum_encode(u8* buf, u64 full_pn, usz nbytes);

/* Recover the full packet number from a truncated value of nbytes bytes,
 * given largest_pn (the largest packet number received in this space). */
u64 pnum_decode(const u8* buf, usz nbytes, u64 largest_pn);

#endif
