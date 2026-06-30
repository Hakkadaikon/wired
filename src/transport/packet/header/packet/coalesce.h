#ifndef QUIC_PACKET_COALESCE_H
#define QUIC_PACKET_COALESCE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.2: several QUIC packets may be coalesced into one UDP
 * datagram. Long-header packets carry a Length field that bounds them;
 * a short-header packet has no length and so must be the last in the
 * datagram. Splitting walks the datagram packet by packet. */

typedef struct {
    const u8 *data;  /* start of this packet within the datagram */
    usz len;         /* its length in bytes */
} quic_coalesced;

/* Cursor over a datagram's coalesced packets. */
typedef struct {
    const u8 *dgram;
    usz total;
    usz off;
} quic_coalesce_iter;

void quic_coalesce_begin(quic_coalesce_iter *it, const u8 *dgram, usz total);

/* Yield the next coalesced packet into *out. Returns 1 if one was produced,
 * 0 when the datagram is exhausted or malformed. A long-header packet is
 * bounded by its Length field; a short-header packet runs to the datagram
 * end (and ends iteration). */
int quic_coalesce_next(quic_coalesce_iter *it, quic_coalesced *out);

#endif
