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
int quic_qpack_ric_decode(u64 encoded, const quic_qpack_ric_ctx *c, u64 *ric);

#endif
