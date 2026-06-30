#ifndef QUIC_VERSION_ABANDON_H
#define QUIC_VERSION_ABANDON_H

#include "transport/version/version/version.h"

/* RFC 9368 3: on receiving a Version Negotiation packet, the client abandons
 * the connection attempt if none of the offered versions (excluding reserved
 * GREASE values) is one it supports. Returns 1 when the connection must be
 * abandoned. */

int quic_version_must_abandon(
    const u32 *offered, usz n, const u32 *we_support, usz n_support);

#endif
