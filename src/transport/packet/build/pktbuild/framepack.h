#ifndef PKTBUILD_FRAMEPACK_H
#define PKTBUILD_FRAMEPACK_H

#include "common/bytes/span/span.h"

/* RFC 9000 12.4: concatenate n_frames pre-encoded frames into one packet
 * payload, in order. On success writes the total length to out->len and
 * returns 1; on cap overflow returns 0. */
int pktbuild_framepack(wired_obuf* out, const wired_span* frames, usz n_frames);

#endif
