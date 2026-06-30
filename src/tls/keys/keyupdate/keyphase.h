#ifndef QUIC_KEYUPDATE_KEYPHASE_H
#define QUIC_KEYUPDATE_KEYPHASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6: the Key Phase bit (0x04) in a short header's first byte
 * carries the low bit of the send key generation, toggling on each update. */

#define QUIC_KEYPHASE_MASK 0x04

/* The Key Phase bit value for a generation: its low bit. */
u8 quic_keyphase_bit(u64 generation);

/* The Key Phase bit carried in a received short-header first byte. */
int quic_keyphase_get(u8 byte0);

/* byte0 with its Key Phase bit set to phase (0 or 1). */
u8 quic_keyphase_set(u8 byte0, int phase);

#endif
