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

#endif
