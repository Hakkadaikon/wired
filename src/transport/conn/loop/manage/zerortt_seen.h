#ifndef MANAGE_ZERORTT_SEEN_H
#define MANAGE_ZERORTT_SEEN_H

#include "common/bytes/span/span.h"

/* RFC 8446 8.1 / RFC 9001 9.2: a server MUST NOT accept 0-RTT for a ticket it
 * has already accepted 0-RTT for once -- single-use enforcement. This is a
 * bounded, process-lifetime tracker of ticket identities, shared by every
 * thread of the process (srvthreads workers) under one spinlock
 * (the sealed pre_shared_key identity bytes, which are unique per issuance
 * since ticket_seal draws a fresh random nonce every call); it feeds
 * zerortt_replay_ok's ticket_first_use argument (zerortt_policy.h).
 * A fixed-size ring: when it is full, the oldest entry is evicted only once
 * it can no longer be replayed (ZERORTT_SEEN_LIVE_SECS after it was
 * recorded); until then a new identity is refused (RFC 8446 8.2: a server
 * that cannot record a ClientHello must not accept its 0-RTT). */

#define ZERORTT_SEEN_CAP 4096

/* RFC 8446 8.2 / 8.3: how long after recording an entry a replay of it can
 * still pass the ticket-age freshness check -- the claimed-vs-measured
 * skew may sit anywhere in [-W, +W] (W = TICKET_FRESHNESS_WINDOW_SECS, 10)
 * when first accepted, so a replay fails it at most 2W later; +1 rounds the
 * one-second clock up. */
#define ZERORTT_SEEN_LIVE_SECS 21

/** Fixed-capacity ring of seen 0-RTT ticket identity digests, for
 * single-use enforcement (RFC 8446 8.1 / RFC 9001 9.2). */
typedef struct {
  u8  digest[ZERORTT_SEEN_CAP][32]; /* SHA-256 of each seen identity */
  usz next;                         /* ring write cursor */
  u64 at[ZERORTT_SEEN_CAP];         /* epoch secs each digest was recorded */
  usz count;                        /* entries filled so far (<= CAP) */
  int lock; /* 1 while one thread runs zerortt_seen_check's find+record */
  /* epoch secs the recording window opened (0 = not yet): see
   * zerortt_seen_pre_start */
  u64 started;
} zerortt_seen;

/* Reset s to empty. */
void zerortt_seen_init(zerortt_seen* s);

/* Check whether identity has been presented to s before; records it either
 * way, as one atomic step against every other thread calling this on s (so
 * a ticket raced on two threads is still a first use only once). Returns 1
 * on first use (identity was not already recorded), 0 on a replay (already
 * recorded). */
int zerortt_seen_check(zerortt_seen* s, wired_span identity);
/* zerortt_seen_check at now_secs (epoch seconds) instead of the clock; a
 * full ring whose oldest entry is still live refuses (returns 0). */
int zerortt_seen_check_at(zerortt_seen* s, wired_span identity, u64 now_secs);

/* RFC 8446 8.2: open s's recording window at now_secs unless it is
 * already open. The server opens it before it issues any ticket (sdrv_init),
 * so every ticket this instance issued has issued_at >= the window start. */
void zerortt_seen_open(zerortt_seen* s, u64 now_secs);
/* RFC 8446 8.2: 1 when a ticket issued at issued_at predates s's window
 * (opening it now if needed) while now_secs is still within
 * ZERORTT_SEEN_LIVE_SECS of the window start -- an earlier server instance
 * may have accepted 0-RTT for a ClientHello on that ticket that is in no
 * record here, and its replay can still pass freshness. A ticket this
 * instance issued cannot carry such a ClientHello.
 * shortcut: second granularity, so a ticket issued by an earlier instance
 * in the very second this one opened its window is not caught; carry
 * milliseconds in the ticket if restarts that fast matter. */
int zerortt_seen_pre_start(zerortt_seen* s, u64 issued_at, u64 now_secs);
/* Open s's recording window at secs, replacing any earlier start (e.g. a
 * server that knows its own start time). */
void zerortt_seen_set_started(zerortt_seen* s, u64 secs);

#endif
