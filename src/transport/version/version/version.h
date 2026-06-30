#ifndef QUIC_VERSION_VERSION_H
#define QUIC_VERSION_VERSION_H

#include "common/platform/sys/syscall.h"

/* QUIC version numbers and the version_information transport parameter
 * (RFC 9368) used for compatible version negotiation. */

#define QUIC_VERSION_1 0x00000001u
#define QUIC_VERSION_2 0x6b3343cfu          /* RFC 9369 */

/* A reserved version matches the 0x?a?a?a?a GREASE pattern (RFC 8999 6) and
 * is never selected. */
int quic_version_is_reserved(u32 version);

/* version_information transport parameter id (RFC 9368 3). */
#define QUIC_TP_VERSION_INFORMATION 0x11
#define QUIC_VI_MAX_AVAILABLE 16

typedef struct {
    u32 chosen;
    usz n_available;
    u32 available[QUIC_VI_MAX_AVAILABLE]; /* in preference order (client) */
} quic_version_info;

/* Encode the version_information TP (id, length, Chosen Version, Available
 * Versions) into buf of cap bytes. Returns bytes written, or 0. */
usz quic_version_info_encode(u8 *buf, usz cap, const quic_version_info *vi);

/* Decode a version_information TP at buf (n readable). Returns bytes
 * consumed, or 0 on malformed input. Chosen must appear in Available for a
 * client-sent parameter; the caller validates that per RFC 9368 4. */
usz quic_version_info_decode(const u8 *buf, usz n, quic_version_info *vi);

#endif
