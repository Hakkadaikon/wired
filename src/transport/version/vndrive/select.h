#ifndef QUIC_VNDRIVE_SELECT_H
#define QUIC_VNDRIVE_SELECT_H

#include "common/platform/sys/syscall.h"

/* RFC 8999 6 / RFC 9000 6.2: from a VN packet the client selects, in its own
 * preference order, the first version present in both its supported set and
 * the server's offered list; if none is common the connection fails. */

/* Writes *chosen with the most-preferred supported version (supported is in
 * preference order, n_sup entries) that also appears in offered (n_off
 * entries) and returns 1; returns 0 if there is no common version. */
int quic_vndrive_select(const u32 *offered, usz n_off,
                        const u32 *supported, usz n_sup, u32 *chosen);

#endif
