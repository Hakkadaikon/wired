#ifndef QUIC_SPIN_SPIN_H
#define QUIC_SPIN_SPIN_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 17.3.1 / 17.4: the latency spin bit. On the highest-numbered
 * packet received, the client sets its outgoing spin to the inverse of the
 * received bit and the server sets it equal. The bit thus flips once per
 * round trip, letting on-path observers measure RTT. It is the third bit
 * (0x20) of a short header's first byte. */

#define QUIC_SPIN_BIT 0x20

/* The spin bit value to send next, given our role (is_server) and the spin
 * bit observed on the peer's highest-numbered packet. Returns 0 or 1. */
int quic_spin_outgoing(int is_server, int peer_spin);

/* Extract the spin bit (0/1) from a short-header first byte. */
int quic_spin_get(u8 byte0);

/* Set or clear the spin bit in a short-header first byte. */
u8 quic_spin_set(u8 byte0, int spin);

/* RFC 9000 17.4: an endpoint SHOULD disable its participation in the spin
 * bit for a random selection of about 1 in 16 connections, sending 0 on
 * every packet for those, so on-path observers cannot rely solely on the
 * spin bit for RTT measurement. `rand_byte` is one uniformly random byte
 * (e.g. from quic_rng_bytes); 1/16 of its values select disablement. */
int quic_spin_disabled(u8 rand_byte);

/* Like quic_spin_outgoing, but sends 0 unconditionally when `disabled` (the
 * connection's own quic_spin_disabled draw) is set. */
int quic_spin_outgoing_ex(int is_server, int peer_spin, int disabled);

#endif
