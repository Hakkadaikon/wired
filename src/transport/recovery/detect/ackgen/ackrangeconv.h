#ifndef QUIC_ACKGEN_ACKRANGECONV_H
#define QUIC_ACKGEN_ACKRANGECONV_H

#include "common/platform/sys/syscall.h"
#include "transport/packet/frame/frame/ack.h"

/* RFC 9000 19.3: quic_ackgen_build_ranges (ackrange.h) writes a gap-encoded
 * intermediate form (First ACK Range Length, then (Gap, Range Length) pairs)
 * -- the layout the wire format itself uses. quic_ack_encode instead wants
 * quic_ack_frame's explicit [hi, lo] quic_ack_range array. This converts one
 * to the other, reusing the same gap arithmetic quic_ack_decode already
 * applies when reading the wire form back (RFC 9000 19.3.1: gap =
 * prev_lo - hi - 2). */

/* raw is quic_ackgen_build_ranges's output (raw[0] = First ACK Range
 * Length, raw[2k-1] = Gap, raw[2k] = Range Length for k >= 1); n is its
 * element count (odd, >= 1). largest is the frame's Largest Acknowledged.
 * Fills f->ranges[]/f->n_ranges. Returns 1 on success, 0 if n is not a valid
 * odd count or the range count would exceed QUIC_ACK_MAX_RANGES. */
int quic_ackrangeconv_to_frame(
    u64 largest, const u64* raw, usz n, quic_ack_frame* f);

#endif
