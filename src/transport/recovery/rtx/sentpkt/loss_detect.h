#ifndef QUIC_SENTPKT_LOSS_DETECT_H
#define QUIC_SENTPKT_LOSS_DETECT_H

#include "transport/recovery/rtx/sentpkt/sentpkt.h"

/* RFC 9002 6.1: packet- and time-threshold loss detection. */
#define QUIC_SENTPKT_PACKET_THRESHOLD 3 /* kPacketThreshold */

/* Inputs to one loss-detection pass. */
typedef struct {
  u64 largest_acked;
  u64 now;
  u64 loss_delay;
} quic_loss_params;

/* Mark in-flight packets as lost when they are kPacketThreshold or more
 * below largest_acked, or older than now - loss_delay. Lost pns are
 * appended to lost.out and *lost.n is set to the count.
 *
 * RFC 9002 7.4: an endpoint MAY ignore the loss of packets that might have
 * arrived before the peer had keys to process them, but MUST NOT ignore the
 * loss of a packet sent after the earliest acknowledged packet in the same
 * packet number space. This scan has no such exemption at all -- every
 * in-flight packet is considered regardless of when it was sent relative to
 * any acknowledged packet -- which trivially satisfies the MUST NOT: nothing
 * sent after the earliest acknowledged packet is ever skipped (9002-059). */
void quic_loss_detect(
    quic_sentpkt* t, const quic_loss_params* p, quic_u64out lost);

#endif
