#ifndef QUIC_VNDRIVE_ACCEPT_H
#define QUIC_VNDRIVE_ACCEPT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 6.2: a client accepts a Version Negotiation packet only as a
 * response to its first Initial (before the handshake completes), and MUST
 * discard it if its own sent version appears in the offered list, which
 * signals a downgrade attempt. */

/* 1 if this VN packet should be processed: handshake not yet complete and
 * sent_version is absent from offered (n entries). 0 otherwise. */
int quic_vndrive_accept(int handshake_complete, u32 sent_version,
                        const u32 *offered, usz n);

#endif
