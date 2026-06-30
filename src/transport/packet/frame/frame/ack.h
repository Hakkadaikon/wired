#ifndef QUIC_FRAME_ACK_H
#define QUIC_FRAME_ACK_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 19.3 ACK frame. Acknowledged packet numbers are encoded as a
 * descending walk from Largest Acknowledged: First Range, then (Gap, Range
 * Length) pairs. We represent the set as an explicit list of inclusive
 * ranges [hi, lo], sorted descending and non-overlapping. */

#define QUIC_FRAME_ACK     0x02
#define QUIC_FRAME_ACK_ECN 0x03
#define QUIC_ACK_MAX_RANGES 32

typedef struct {
    u64 hi; /* highest packet number in this range */
    u64 lo; /* lowest packet number in this range */
} quic_ack_range;

typedef struct {
    u64 ack_delay;
    usz n_ranges;
    quic_ack_range ranges[QUIC_ACK_MAX_RANGES]; /* descending, ranges[0].hi = largest */
    u8  has_ecn;   /* 1 -> type 0x03 with the ECN counts below (RFC 9000 19.3.2) */
    u64 ect0;
    u64 ect1;
    u64 ce;
} quic_ack_frame;

/* Encode an ACK frame (type 0x02, no ECN) into buf of cap bytes.
 * Returns bytes written, or 0 on overflow / empty / malformed ranges. */
usz quic_ack_encode(u8 *buf, usz cap, const quic_ack_frame *f);

/* Decode an ACK frame at buf (n readable, type byte 0x02 at buf[0]).
 * Fills *f and returns bytes consumed, or 0 on malformed / truncated input. */
usz quic_ack_decode(const u8 *buf, usz n, quic_ack_frame *f);

#endif
