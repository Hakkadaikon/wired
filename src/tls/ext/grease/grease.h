#ifndef QUIC_GREASE_GREASE_H
#define QUIC_GREASE_GREASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9287 Greasing the QUIC Bit. The "QUIC Bit" is the second-most
 * significant bit of the first byte (0x40, the fixed bit). When both peers
 * advertise the grease_quic_bit transport parameter, an endpoint may send
 * packets with this bit set to 0 and must accept such packets. */

#define QUIC_TP_GREASE_QUIC_BIT 0x2ab2
#define QUIC_BIT_MASK 0x40

/* Encode the grease_quic_bit transport parameter (id, empty value) into buf
 * of cap bytes. Returns bytes written, or 0. */
usz quic_grease_encode(u8 *buf, usz cap);

/* Decode a grease_quic_bit parameter at buf (n readable). Requires an empty
 * value (RFC 9287 3). Returns bytes consumed, or 0 on a non-empty value or
 * truncated input. */
usz quic_grease_decode(const u8 *buf, usz n);

/* Whether a received first byte is acceptable. When the peer advertised
 * grease_quic_bit (peer_greases != 0), a cleared QUIC Bit is accepted;
 * otherwise the QUIC Bit must be set. */
int quic_grease_accept_byte0(u8 byte0, int peer_greases);

#endif
