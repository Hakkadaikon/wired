#ifndef QUIC_KUSWITCH_PHASEBIT_H
#define QUIC_KUSWITCH_PHASEBIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.2: the Key Phase bit of a short-header packet reflects the send
 * key generation's low bit and flips on each key update. */

/* The Key Phase bit value (0 or 1) for a send generation. */
u8 quic_kuswitch_phase_bit(u64 generation);

/* Set the Key Phase bit (0x04) in a short-header first byte to match the
 * generation. */
void quic_kuswitch_apply_phase(u8 *byte0, u64 generation);

#endif
