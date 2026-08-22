#ifndef VERSION_VERSELECT_H
#define VERSION_VERSELECT_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/verinfo.h"
#include "transport/version/version/version.h"

/* RFC 9368 2.2 / 3: validation and selection over a received Version
 * Information structure. */

/* The Chosen Version a peer reports must equal the version actually used on
 * the packet carrying it; otherwise VERSION_NEGOTIATION_ERROR. Returns 1/0. */
int verinfo_chosen_ok(u32 chosen, u32 actual_packet_version);

/* RFC 9368 3: the peer's Available Versions list is in the peer's descending
 * preference order. Pick the first entry of that list we support that is
 * compatible with the peer's Chosen Version, ignoring reserved (GREASE)
 * entries. Returns 1 with *out set, or 0 if none. */
int verinfo_pick_compatible(
    const version_information* vi, verlist we_support, u32* out);

#endif
