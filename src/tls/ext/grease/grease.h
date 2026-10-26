#ifndef GREASE_GREASE_H
#define GREASE_GREASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9287 Greasing the QUIC Bit. The "QUIC Bit" is the second-most
 * significant bit of the first byte (0x40, the fixed bit). When both peers
 * advertise the grease_quic_bit transport parameter, an endpoint may send
 * packets with this bit set to 0 and must accept such packets. */

#define TP_GREASE_QUIC_BIT 0x2ab2
#define BIT_MASK 0x40

/* Encode the grease_quic_bit transport parameter (id, empty value) into buf
 * of cap bytes. Returns bytes written, or 0. */
usz grease_encode(u8* buf, usz cap);

#endif
