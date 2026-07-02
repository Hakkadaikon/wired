#ifndef QUIC_RTXBYTES_COLLECT_H
#define QUIC_RTXBYTES_COLLECT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/recovery/rtx/rtxbytes/rtxstore.h"

/* RFC 9002 6, 13.3: given the packet numbers declared lost, look up each
 * packet's kept frame bytes (rtxstore) and rebuild the retransmittable ones,
 * concatenating them into out for transmission in a new packet. pns not held
 * by the store are skipped. */

/* A read-only view of lost packet numbers. */
typedef struct {
  const u64 *pns;
  usz        n;
} quic_lost_pns;

/* Returns 1 on success with out->len set to the concatenated length, or 0 if
 * out->cap is too small. */
int quic_rtxbytes_collect(
    const quic_rtxbytes *st, quic_lost_pns lost, quic_obuf *out);

#endif
