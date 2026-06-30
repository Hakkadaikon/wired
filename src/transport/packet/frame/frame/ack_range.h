#ifndef QUIC_FRAME_ACK_RANGE_H
#define QUIC_FRAME_ACK_RANGE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.3.1: ACK ranges descend from Largest Acknowledged without
 * overlap. First ACK Range cannot drop below packet number zero, and each
 * (Gap, ACK Range Length) pair must not underflow past the prior range. */

/* First ACK Range: largest - first_range >= 0. */
int quic_ack_range_ok(u64 largest, u64 first_range);

/* Next range high = smallest - gap - 2; require smallest >= gap+range_len+2
 * so neither the next high nor its low underflows below zero. */
int quic_ack_gap_ok(u64 smallest, u64 gap, u64 range_len);

#endif
