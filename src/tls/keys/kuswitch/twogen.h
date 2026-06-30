#ifndef QUIC_KUSWITCH_TWOGEN_H
#define QUIC_KUSWITCH_TWOGEN_H

#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 6.3/6.5: an endpoint keeps the current 1-RTT keys and, after a key
 * update, the immediately prior keys, so packets in flight under the old key
 * can still be decrypted until the retention period ends. A received packet's
 * Key Phase bit selects which generation decrypts it. */

typedef struct {
    quic_initial_keys cur; /* current generation's keys */
    quic_initial_keys old; /* prior generation's keys (valid when have_old) */
    u64 generation;        /* current send/receive generation, starts at 0 */
    int have_old;          /* 1 while old is populated and retained */
} quic_kuswitch_state;

/* Initialise at generation 0 with the first 1-RTT keys; no old key yet. */
void quic_kuswitch_init(quic_kuswitch_state *state,
                        const quic_initial_keys *gen0);

/* RFC 9001 6.3: advance to the next generation. The current keys become old
 * (retained), and next becomes current; generation increments. */
void quic_kuswitch_rotate(quic_kuswitch_state *state,
                          const quic_initial_keys *next);

/* RFC 9001 6.3: choose the keys that decrypt a packet carrying recv_phase_bit.
 * Returns 1 with *keys set when a matching generation is available, 0 when the
 * bit asks for an old generation that is not (or no longer) retained. */
int quic_kuswitch_key_for_phase(const quic_kuswitch_state *state,
                                int recv_phase_bit,
                                const quic_initial_keys **keys);

/* RFC 9001 6.5: drop the retained old key once its retention period ends. */
void quic_kuswitch_discard_old(quic_kuswitch_state *state);

#endif
