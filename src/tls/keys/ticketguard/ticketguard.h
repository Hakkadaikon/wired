#ifndef QUIC_TICKETGUARD_TICKETGUARD_H
#define QUIC_TICKETGUARD_TICKETGUARD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Single-use tracking for session tickets (RFC 8446 8.1 anti-replay,
 * RFC 9001 9.2): each sealed ticket begins with its randomly generated
 * nonce, so its leading bytes fingerprint it; the first presentation is
 * accepted and recorded, a second one is a replay.
 * ponytail: a fixed ring of recent fingerprints — an entry evicted by
 * newer tickets could replay past the window; widen QUIC_TICKETGUARD_CAP
 * (or move to a time-bucketed filter) if the issue rate ever makes that
 * window meaningful. */

#define QUIC_TICKETGUARD_CAP 64
#define QUIC_TICKETGUARD_FP 16

typedef struct {
  u8  fp[QUIC_TICKETGUARD_CAP][QUIC_TICKETGUARD_FP]; /**< seen fingerprints */
  int live[QUIC_TICKETGUARD_CAP]; /**< 1 when the slot holds one */
  usz next;                       /**< ring write position */
} quic_ticketguard;

/** Empty the seen set. */
void quic_ticketguard_init(quic_ticketguard* g);

/** Present one sealed ticket: the first time its fingerprint is seen it is
 * recorded and accepted; a repeat — or a ticket too short to fingerprint —
 * is refused.
 * @return 1 on first use, 0 on replay or malformed input. */
int quic_ticketguard_first_use(quic_ticketguard* g, quic_span sealed);

#endif
