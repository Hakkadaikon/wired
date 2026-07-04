#ifndef QUIC_VERSION_VERSELECT_H
#define QUIC_VERSION_VERSELECT_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/verinfo.h"
#include "transport/version/version/version.h"

/* RFC 9368 2.2 / 3: validation and selection over a received Version
 * Information structure. */

/* The Chosen Version a peer reports must equal the version actually used on
 * the packet carrying it; otherwise VERSION_NEGOTIATION_ERROR. Returns 1/0. */
int quic_verinfo_chosen_ok(u32 chosen, u32 actual_packet_version);

/* Pick the most-preferred version both sides support and that is compatible
 * with the peer's Chosen Version, ignoring reserved (GREASE) entries. Returns
 * 1 with *out set, or 0 if none. we_support is in our preference order. */
int quic_verinfo_pick_compatible(
    const quic_version_information* vi, quic_verlist we_support, u32* out);

#endif
