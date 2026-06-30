#ifndef QUIC_HRR_GROUP_H
#define QUIC_HRR_GROUP_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.1.4: extract the key_share selected_group from a HelloRetryRequest
 * (handshake message type 0x02 | length(3) | body). The client must resend its
 * ClientHello with a key_share for this group. On success writes the group to
 * *group and returns 1; returns 0 if the key_share extension is absent or
 * malformed. */
int quic_hrr_selected_group(const u8 *hrr_msg, usz len, u16 *group);

#endif
