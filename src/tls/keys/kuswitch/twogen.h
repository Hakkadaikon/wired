#ifndef QUIC_KUSWITCH_TWOGEN_H
#define QUIC_KUSWITCH_TWOGEN_H

#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 6.3/6.5: an endpoint keeps the current 1-RTT keys and, after a key
 * update, the immediately prior keys, so packets in flight under the old key
 * can still be decrypted until the retention period ends. A received packet's
 * Key Phase bit selects which generation decrypts it. */

/** RFC 9001 6.3/6.5 two-generation key state: the current 1-RTT keys and,
 * once a Key Update has happened, the immediately prior generation's keys
 * (retained so packets still in flight under the old key keep decrypting
 * until the retention period ends). */
typedef struct {
  initial_keys cur;        /**< current generation's keys */
  initial_keys old;        /**< prior generation's keys (valid when have_old) */
  u64          generation; /**< current send/receive generation, starts at 0 */
  int          have_old;   /**< 1 while old is populated and retained */
} kuswitch_state;

/* Initialise at generation 0 with the first 1-RTT keys; no old key yet. */
void kuswitch_init(kuswitch_state* state, const initial_keys* gen0);

/* RFC 9001 6.3: advance to the next generation. The current keys become old
 * (retained), and next becomes current; generation increments. */
void kuswitch_rotate(kuswitch_state* state, const initial_keys* next);

/* RFC 9001 6.3: choose the keys that decrypt a packet carrying recv_phase_bit.
 * Returns 1 with *keys set when a matching generation is available, 0 when the
 * bit asks for an old generation that is not (or no longer) retained. */
int kuswitch_key_for_phase(
    const kuswitch_state* state, int recv_phase_bit, const initial_keys** keys);

/* RFC 9001 6.5: drop the retained old key once its retention period ends. */
void kuswitch_discard_old(kuswitch_state* state);

#endif
