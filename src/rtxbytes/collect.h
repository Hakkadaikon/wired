#ifndef QUIC_RTXBYTES_COLLECT_H
#define QUIC_RTXBYTES_COLLECT_H

#include "sys/syscall.h"

#include "rtxbytes/rtxstore.h"

/* RFC 9002 6, 13.3: given the packet numbers declared lost, look up each
 * packet's kept frame bytes (rtxstore) and rebuild the retransmittable ones,
 * concatenating them into out for transmission in a new packet. pns not held
 * by the store are skipped. */

/* Returns 1 on success with *out_len set to the concatenated length, or 0 if
 * out is too small. */
int quic_rtxbytes_collect(const quic_rtxbytes *st, const u64 *lost_pns,
                          usz n, u8 *out, usz cap, usz *out_len);

#endif
