#ifndef MANAGE_ZERORTT_SEEN_H
#define MANAGE_ZERORTT_SEEN_H

#include "common/bytes/span/span.h"

/* RFC 8446 8.1 / RFC 9001 9.2: a server MUST NOT accept 0-RTT for a ticket it
 * has already accepted 0-RTT for once -- single-use enforcement. This is a
 * bounded, process-lifetime, single-process tracker of ticket identities
 * (the sealed pre_shared_key identity bytes, which are unique per issuance
 * since ticket_seal draws a fresh random nonce every call); it feeds
 * zerortt_replay_ok's ticket_first_use argument (zerortt_policy.h).
 * ponytail: fixed-size ring, oldest entry evicted on overflow -- no
 * persistence/cross-process sharing (this SDK is one process per server), a
 * ticket also expires on its own lifetime so an evicted-then-replayed entry
 * is bounded by that, not unbounded. */

#define ZERORTT_SEEN_CAP 4096

/** Fixed-capacity ring of seen 0-RTT ticket identity digests, for
 * single-use enforcement (RFC 8446 8.1 / RFC 9001 9.2). */
typedef struct {
  u8  digest[ZERORTT_SEEN_CAP][32]; /* SHA-256 of each seen identity */
  usz next;                         /* ring write cursor */
  usz count;                        /* entries filled so far (<= CAP) */
} zerortt_seen;

/* Reset s to empty. */
void zerortt_seen_init(zerortt_seen* s);

/* Check whether identity has been presented to s before; records it either
 * way. Returns 1 on first use (identity was not already recorded), 0 on a
 * replay (already recorded). */
int zerortt_seen_check(zerortt_seen* s, wired_span identity);

#endif
