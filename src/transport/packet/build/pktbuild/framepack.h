#ifndef QUIC_PKTBUILD_FRAMEPACK_H
#define QUIC_PKTBUILD_FRAMEPACK_H

#include "common/bytes/span/span.h"

/* RFC 9000 12.4: concatenate n_frames pre-encoded frames into one packet
 * payload, in order. On success writes the total length to out->len and
 * returns 1; on cap overflow returns 0. */
int quic_pktbuild_framepack(
    quic_obuf* out, const quic_span* frames, usz n_frames);

#endif
