#ifndef RECOVERY_LOSSDETECT_H
#define RECOVERY_LOSSDETECT_H

#include "common/platform/sys/syscall.h"

/* RFC 9002 6.1: a packet is lost by the packet threshold or the time
 * threshold (the latter's loss_delay is lossdrive_loss_delay). */

#define LOSS_PACKET_THRESHOLD 3 /* kPacketThreshold */
#define LOSS_TIME_NUM 9         /* kTimeThreshold = 9/8 */
#define LOSS_TIME_DEN 8

/* True when pn is kPacketThreshold or more below largest_acked. */
int loss_by_packet(u64 largest_acked, u64 pn);

#endif
