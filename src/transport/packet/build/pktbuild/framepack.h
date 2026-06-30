#ifndef QUIC_PKTBUILD_FRAMEPACK_H
#define QUIC_PKTBUILD_FRAMEPACK_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 12.4: concatenate n_frames pre-encoded frames into one packet
 * payload of cap bytes, in order. Each frames[i] is frame_lens[i] bytes.
 * On success writes the total length to *out_len and returns 1; on cap
 * overflow writes nothing and returns 0. */
int quic_pktbuild_framepack(u8 *payload, usz cap, const u8 *const *frames,
                            const usz *frame_lens, usz n_frames, usz *out_len);

#endif
