#ifndef QUIC_VNDRIVE_SELECT_H
#define QUIC_VNDRIVE_SELECT_H

#include "common/platform/sys/syscall.h"
#include "transport/version/version/version.h"

/* RFC 8999 6 / RFC 9000 6.2: from a VN packet the client selects, in its own
 * preference order, the first version present in both its supported set and
 * the server's offered list; if none is common the connection fails. */

/* Writes *chosen with the most-preferred version in `supported` (preference
 * order) that also appears in `offered` and returns 1; returns 0 if there is
 * no common version. */
int quic_vndrive_select(
    quic_verlist offered, quic_verlist supported, u32 *chosen);

#endif
