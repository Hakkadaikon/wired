#ifndef QUIC_HP_HPSAMPLE_H
#define QUIC_HP_HPSAMPLE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4.2: the 16-byte header-protection sample starts 4 bytes after
 * the start of the packet number field (sample_offset = pn_offset + 4). */
usz quic_hp_sample_offset(usz pn_offset);

/* True if a 16-byte sample fits within a packet of packet_len bytes. */
int quic_hp_sample_ok(usz packet_len, usz sample_offset);

#endif
