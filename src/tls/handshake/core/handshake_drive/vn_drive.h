#ifndef QUIC_HANDSHAKE_DRIVE_VN_DRIVE_H
#define QUIC_HANDSHAKE_DRIVE_VN_DRIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 8999 6 / RFC 9000 6: client reception of a Version Negotiation packet.
 * Pick a mutually supported version and reject VN once the handshake has
 * progressed (downgrade protection). */

/* Choose a version from the VN packet's supported-version list (vn_versions:
 * n_versions entries, each 4 big-endian bytes) against our my_versions
 * (my_count entries, in preference order). On a match writes *chosen and
 * returns 1; returns 0 with no match. */
int quic_vn_choose(const u8 *vn_versions, usz n_versions,
                   const u32 *my_versions, usz my_count, u32 *chosen);

/* RFC 9000 6.2: a VN packet is only acceptable as a response to the first
 * Initial. Returns 0 (ignore) once the handshake has started. */
int quic_vn_acceptable(int handshake_started);

#endif
