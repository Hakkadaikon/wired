#ifndef QUIC_KEYUPDATE_KEYUPDATE_H
#define QUIC_KEYUPDATE_KEYUPDATE_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6: 1-RTT key update. The send key generation is a monotonic
 * counter; the Key Phase bit is its low bit. At most two adjacent
 * generations are retained at once, and a new update may not begin until
 * the previous one is acknowledged. */

typedef struct {
    u64 gen;           /* current send key generation */
    u64 lowest;        /* lowest retained generation (gen-1 or gen) */
    int updating;      /* 1 while an initiated update is unacknowledged */
} quic_keyupdate;

void quic_keyupdate_init(quic_keyupdate *k);

/* The Key Phase bit carried in outgoing 1-RTT packets. */
u8 quic_keyupdate_phase(const quic_keyupdate *k);

/* Begin a key update. Refused (returns 0) while a prior update is
 * unacknowledged; on success advances the generation, toggles the phase,
 * and retains exactly {gen-1, gen}. */
int quic_keyupdate_initiate(quic_keyupdate *k);

/* Acknowledge the in-flight update, allowing the next one. */
void quic_keyupdate_acked(quic_keyupdate *k);

/* Follow a peer that updated first (its Key Phase is one generation ahead).
 * Refused while our own update is unacknowledged. Returns 1 if followed. */
int quic_keyupdate_follow(quic_keyupdate *k);

/* Whether generation g can currently be decrypted: a retained generation,
 * or exactly one ahead (the next generation, derived on demand). Two or more
 * generations ahead is a KEY_UPDATE_ERROR and returns 0. */
int quic_keyupdate_can_decrypt(const quic_keyupdate *k, u64 g);

#endif
