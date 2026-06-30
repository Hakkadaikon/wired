#ifndef QUIC_RTXDRIVE_SELECT_H
#define QUIC_RTXDRIVE_SELECT_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/rtx/rtxbytes/rtxstore.h"

/* RFC 9002 13.3: a lost packet's frames are retransmitted, except ACK and
 * PADDING. Given a lost packet number, look up the frame bytes the store kept
 * for it and decide whether they should be resent.
 *
 * Returns 1 if pn is held by the store (with *is_retransmittable set to 1 when
 * the frame must be resent, 0 for ACK/PADDING/malformed). Returns 0 if pn is
 * not held. */
int quic_rtxdrive_select(
    const quic_rtxbytes *store, u64 lost_pn, int *is_retransmittable);

#endif
