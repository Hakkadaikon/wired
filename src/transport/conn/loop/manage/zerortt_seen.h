#ifndef QUIC_MANAGE_ZERORTT_SEEN_H
#define QUIC_MANAGE_ZERORTT_SEEN_H

#include "common/bytes/span/span.h"

/* RFC 8446 8.1 / RFC 9001 9.2: a server MUST NOT accept 0-RTT for a ticket it
 * has already accepted 0-RTT for once -- single-use enforcement. This is a
 * bounded, process-lifetime, single-process tracker of ticket identities
 * (the sealed pre_shared_key identity bytes, which are unique per issuance
 * since quic_ticket_seal draws a fresh random nonce every call); it feeds
 * quic_zerortt_replay_ok's ticket_first_use argument (zerortt_policy.h).
 * ponytail: fixed-size ring, oldest entry evicted on overflow -- no
 * persistence/cross-process sharing (this SDK is one process per server), a
 * ticket also expires on its own lifetime so an evicted-then-replayed entry
 * is bounded by that, not unbounded. */

#define QUIC_ZERORTT_SEEN_CAP 4096

typedef struct {
  u8  digest[QUIC_ZERORTT_SEEN_CAP][32]; /* SHA-256 of each seen identity */
  usz next;                              /* ring write cursor */
  usz count;                             /* entries filled so far (<= CAP) */
} quic_zerortt_seen;

/* Reset s to empty. */
void quic_zerortt_seen_init(quic_zerortt_seen* s);

/* Check whether identity has been presented to s before; records it either
 * way. Returns 1 on first use (identity was not already recorded), 0 on a
 * replay (already recorded). */
int quic_zerortt_seen_check(quic_zerortt_seen* s, quic_span identity);

#endif
