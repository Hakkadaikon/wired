#ifndef QUIC_RTXDRIVE_BUILD_H
#define QUIC_RTXDRIVE_BUILD_H

#include "common/platform/sys/syscall.h"
#include "transport/recovery/rtx/rtxbytes/rtxstore.h"

/* RFC 9002 13.3: retransmit a lost packet's frames in a new packet by copying
 * the original frame bytes verbatim (a new packet number carries them). This
 * is the real-bytes replacement for a PING stand-in.
 *
 * Restores the frame bytes the store kept for lost_pn into out. A
 * retransmittable frame yields its bytes; a non-retransmittable frame
 * (ACK/PADDING) or a pn not held yields out->len = 0. Returns 1 on success, 0
 * if out->cap is too small. */
int quic_rtxdrive_build(
    const quic_rtxbytes *store, u64 lost_pn, quic_obuf *out);

#endif
