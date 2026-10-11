#ifndef QPACKDYN_DEC_STREAM_H
#define QPACKDYN_DEC_STREAM_H

#include "common/bytes/span/span.h"

/* RFC 9204 4.4. What this decoder owes the peer's encoder on its decoder
 * stream: Section Acknowledgments (4.4.1) queued as sections decode, and an
 * Insert Count Increment (4.4.3) for every insert no acknowledgment already
 * covered. Stream Cancellation (4.4.2) is never sent. */

/** Queued Section Acknowledgment bytes (a few bytes each). */
#define QDYN_DEC_ACKS_MAX 64
/** Worst-case pending output: the queued acks plus one increment. */
#define QDYN_DEC_OUT_MAX (QDYN_DEC_ACKS_MAX + 10)

/** RFC 9204 4.4. Zero-initialise. */
typedef struct {
  u8  acks[QDYN_DEC_ACKS_MAX]; /**< encoded, unsent Section Acks */
  usz acks_len;
  u64 acked; /**< Known Received Count once acks and increments land */
} qdyn_dec;

/* RFC 9204 4.4.1: queue a Section Acknowledgment for stream_id when its
 * section's Required Insert Count ric is non-zero. ponytail: a full queue
 * drops the ack (the encoder only keeps those entries pinned longer). */
void qdyn_dec_section_ack(qdyn_dec* d, u64 stream_id, u64 ric);

/* RFC 9204 4.4: write the owed bytes -- queued acks, then an Insert Count
 * Increment up to `inserts` (the table's total insert count) -- into out.
 * Consumes nothing; returns out->len. */
usz qdyn_dec_pending(const qdyn_dec* d, u64 inserts, wired_obuf* out);

/* The bytes qdyn_dec_pending produced for `inserts` were sent. */
void qdyn_dec_sent(qdyn_dec* d, u64 inserts);

#endif
