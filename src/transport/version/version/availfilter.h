#ifndef QUIC_VERSION_AVAILFILTER_H
#define QUIC_VERSION_AVAILFILTER_H

#include "common/platform/sys/syscall.h"

/* RFC 9368 3: Available Versions may contain reserved (GREASE) versions that
 * must be ignored when negotiating. A version is usable if it is not
 * reserved. */
int quic_verinfo_is_usable(u32 version);

#endif
