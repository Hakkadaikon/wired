#ifndef QUIC_SENTMETA_DETECT_LOSS_H
#define QUIC_SENTMETA_DETECT_LOSS_H

#include "transport/recovery/rtx/sentmeta/record.h"

/* RFC 9002 6.1: packet threshold (kPacketThreshold). */
#define QUIC_SENTMETA_PACKET_THRESHOLD 3

/* Inputs to one loss-detection pass. */
typedef struct {
  u64 largest_acked;
  u64 now;
  u64 loss_delay;
} quic_sentmeta_loss_in;

/* An output slice for accumulated lost PNs: out[0..*n) is filled, *n starts
 * at the caller's count and is advanced. Must hold QUIC_SENTMETA_CAP. */
typedef struct {
  u64* out;
  usz* n;
} quic_sentmeta_u64out;

/* RFC 9002 6.1: declare lost any tracked packet at or below largest_acked by
 * kPacketThreshold (6.1.1) or sent before now - loss_delay (6.1.2). Lost PNs
 * are written to lost.out / *lost.n and removed from the ring, dropping their
 * bytes from total_in_flight (7.4). */
void quic_sentmeta_detect_loss(
    quic_sentmeta*               m,
    const quic_sentmeta_loss_in* in,
    quic_sentmeta_u64out         lost);

#endif
