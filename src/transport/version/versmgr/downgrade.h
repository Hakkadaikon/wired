#ifndef QUIC_VERSMGR_DOWNGRADE_H
#define QUIC_VERSMGR_DOWNGRADE_H

#include "common/platform/sys/syscall.h"

/* RFC 9368 6: the negotiated version must be consistent with the server's
 * Available Versions. A downgrade is detected when negotiated is absent from
 * server_available, or when a more-preferred usable version precedes it
 * (the server should have chosen that one). */

/* 1 if no downgrade: negotiated is present in server_available (preference
 * order) and no usable version precedes it. 0 if a downgrade is suspected. */
int quic_vers_no_downgrade(u32 negotiated, const u32 *server_available, usz n);

#endif
