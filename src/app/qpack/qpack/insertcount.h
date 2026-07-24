#ifndef QUIC_QPACK_INSERTCOUNT_H
#define QUIC_QPACK_INSERTCOUNT_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5.1.1. Required Insert Count is transmitted as EncodedInsertCount
 * to bound it relative to MaxEntries. max_entries is the dynamic table capacity
 * divided by 32 (RFC 9204 3.2.2). */

/* Encode a Required Insert Count. Returns the EncodedInsertCount. */
u64 quic_qpack_ric_encode(u64 ric, u64 max_entries);

/* The decoder-side table state an EncodedInsertCount is resolved against. */
typedef struct {
  u64 max_entries;
  u64 total_inserts;
} quic_qpack_ric_ctx;

/* Decode an EncodedInsertCount against the table state. Writes the Required
 * Insert Count to *ric. Returns 1 on success, 0 if the encoding is invalid. */
int quic_qpack_ric_decode(u64 encoded, const quic_qpack_ric_ctx* c, u64* ric);

/* RFC 9204 2.1.2 / 2.2.1. The lowest Required Insert Count with which a field
 * section could be decoded is 0 if it makes no dynamic table references, or
 * one larger than the largest absolute index of any such reference
 * (max_abs_ref, ignored when has_dynamic_ref is 0). Returns 1 if ric is at
 * least that expected minimum, 0 if ric is smaller than expected -- the
 * caller treats 0 as a connection error of type QPACK_DECOMPRESSION_FAILED. */
int quic_qpack_ric_min_ok(u64 ric, int has_dynamic_ref, u64 max_abs_ref);

/* RFC 9204 4.4.3. An Insert Count Increment instruction received on the
 * decoder stream is invalid, and MUST be treated by the encoder as a
 * connection error of type QPACK_DECODER_STREAM_ERROR, if increment is zero
 * or if applying it would raise the Known Received Count (Section 2.1.4)
 * beyond total_inserts, the number of dynamic table insertions and
 * duplications the encoder has actually sent. Returns 1 if valid, 0 if
 * invalid. */
int quic_qpack_incr_valid(u64 known_received, u64 increment, u64 total_inserts);

/* RFC 9204 4.4.1. A Section Acknowledgment instruction refers to a stream
 * ID; the encoder tracks, per stream, how many of its own encoded field
 * sections with a non-zero Required Insert Count on that stream remain
 * unacknowledged (pending_acks). Receiving a Section Acknowledgment when
 * pending_acks is already 0 means every such field section on that stream
 * has already been acknowledged, which MUST be treated by the encoder as a
 * connection error of type QPACK_DECODER_STREAM_ERROR. Returns 1 if valid
 * (pending_acks > 0), 0 if invalid. */
int quic_qpack_section_ack_valid(u64 pending_acks);

#endif
