#ifndef QUIC_VERSION_COMPAT_H
#define QUIC_VERSION_COMPAT_H

#include "transport/version/version/version.h"

/* RFC 9368 2 / RFC 9369 3.1: two versions are "compatible" when a server can
 * continue a connection begun in one with the other without a new round trip.
 * A version is compatible with itself; v1 and v2 are compatible with each
 * other (RFC 9369 3.1). */

int quic_version_compatible(u32 a, u32 b);

#endif
