#ifndef QUIC_GREASE_BITSET_H
#define QUIC_GREASE_BITSET_H

#include "tls/ext/grease/grease.h" /* u8, QUIC_BIT_MASK */

/* RFC 9287 3: when the peer advertised grease_quic_bit, an endpoint may set
 * the QUIC Bit (0x40) of sent packets to a random value. */

/* Whether this endpoint is permitted to clear the QUIC Bit: only when the
 * peer advertised grease_quic_bit. */
int quic_greasebit_may_clear(int peer_advertised);

/* Apply the QUIC Bit to a first byte: clear 0x40 when clear != 0, else set it.
 */
u8 quic_greasebit_apply(u8 byte0, int clear);

#endif
