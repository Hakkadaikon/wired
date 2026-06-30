#ifndef QUIC_GREASE_SRESET_BIT_H
#define QUIC_GREASE_SRESET_BIT_H

#include "tls/ext/grease/grease.h" /* u8 */

/* RFC 9287 3.1: a stateless reset packet is made to look like a random short
 * header packet, so any QUIC Bit value is permitted regardless of grease
 * negotiation. */
int quic_greasebit_sreset_ok(u8 byte0);

#endif
