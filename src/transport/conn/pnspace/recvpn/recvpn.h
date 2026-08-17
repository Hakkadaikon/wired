#ifndef QUIC_RECVPN_RECVPN_H
#define QUIC_RECVPN_RECVPN_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 13.2: a receiver tracks which packet numbers it has seen so it can
 * drop duplicates and acknowledge the rest. We keep the largest number seen
 * and a sliding bitmap of the window below it, which is enough to detect
 * duplicates and to find the contiguous run for the ACK's first range. */

#define QUIC_RECVPN_WINDOW \
  64 /* packets below `largest` tracked in the bitmap */

/** Sliding window of received packet numbers for one packet number space. */
typedef struct {
  u64 largest; /**< highest packet number recorded (valid once any seen) */
  u64 bitmap;  /**< bit i set => (largest - 1 - i) was received */
  int any;     /**< whether anything has been recorded yet */
} recvpn;

void recvpn_init(recvpn* r);

/* Whether packet number pn has already been recorded (a duplicate). */
int recvpn_seen(const recvpn* r, u64 pn);

/* Record packet number pn as received. Numbers older than the window are
 * ignored (treated as already acknowledged). */
void recvpn_record(recvpn* r, u64 pn);

/* The first ACK range: the count of contiguous packets ending at `largest`
 * that have been received (0 if none recorded). */
u64 recvpn_first_range(const recvpn* r);

#endif
