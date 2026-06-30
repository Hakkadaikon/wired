#ifndef QUIC_VERSION_VERINFO_H
#define QUIC_VERSION_VERINFO_H

#include "common/platform/sys/syscall.h"

/* RFC 9368 3: the Version Information structure carried in the
 * version_information transport parameter. It is the Chosen Version (4 bytes)
 * followed by the Available Versions list (4 bytes each). */

#define QUIC_VI_MAX_AVAILABLE 16

typedef struct {
    u32 chosen;
    usz count;
    u32 available[QUIC_VI_MAX_AVAILABLE]; /* preference order */
} quic_version_information;

/* Encode chosen + available into buf of cap bytes. Returns bytes written, or
 * 0 if cap is too small or count exceeds QUIC_VI_MAX_AVAILABLE. */
usz quic_verinfo_encode(u8 *buf, usz cap, const quic_version_information *vi);

/* Decode n bytes (a multiple of 4, at least 4) into vi. Returns bytes
 * consumed, or 0 if truncated, misaligned, or too many Available Versions. */
usz quic_verinfo_decode(const u8 *buf, usz n, quic_version_information *vi);

#endif
