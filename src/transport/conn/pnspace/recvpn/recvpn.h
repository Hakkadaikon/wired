#ifndef QUIC_RECVPN_RECVPN_H
#define QUIC_RECVPN_RECVPN_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 13.2: a receiver tracks which packet numbers it has seen so it can
 * drop duplicates and acknowledge the rest. We keep the largest number seen
 * and a sliding bitmap of the window below it, which is enough to detect
 * duplicates and to find the contiguous run for the ACK's first range. */

#define QUIC_RECVPN_WINDOW 64 /* packets below `largest` tracked in the bitmap */

typedef struct {
    u64 largest;  /* highest packet number recorded (valid once any seen) */
    u64 bitmap;   /* bit i set => (largest - 1 - i) was received */
    int any;      /* whether anything has been recorded yet */
} quic_recvpn;

void quic_recvpn_init(quic_recvpn *r);

/* Whether packet number pn has already been recorded (a duplicate). */
int quic_recvpn_seen(const quic_recvpn *r, u64 pn);

/* Record packet number pn as received. Numbers older than the window are
 * ignored (treated as already acknowledged). */
void quic_recvpn_record(quic_recvpn *r, u64 pn);

/* The first ACK range: the count of contiguous packets ending at `largest`
 * that have been received (0 if none recorded). */
u64 quic_recvpn_first_range(const quic_recvpn *r);

#endif
