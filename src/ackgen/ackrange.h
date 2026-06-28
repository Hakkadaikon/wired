#ifndef QUIC_ACKGEN_ACKRANGE_H
#define QUIC_ACKGEN_ACKRANGE_H

#include "sys/syscall.h"

/* RFC 9000 19.3: an ACK frame reports the Largest Acknowledged packet number
 * and a descending list of contiguous ranges separated by gaps. This builds
 * those ranges from an ascending, deduplicated array of received packet
 * numbers.
 *
 * Output layout (descending, matching wire order):
 *   largest          = highest received packet number
 *   ranges[0]        = First ACK Range length (count-1 of the top block)
 *   ranges[2k-1]     = Gap to the next block (RFC 19.3.1 encoding)
 *   ranges[2k]       = ACK Range Length of block k (count-1)
 *   n_ranges         = number of u64 values written into ranges
 *
 * cap bounds ranges. Returns 1 on success, 0 if n is 0 or cap is too small. */
int quic_ackgen_build_ranges(const u64 *received_pns, usz n, u64 *largest,
                             u64 *ranges, usz *n_ranges, usz cap);

#endif
