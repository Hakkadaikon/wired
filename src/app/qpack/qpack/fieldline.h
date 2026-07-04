#ifndef QUIC_QPACK_FIELDLINE_H
#define QUIC_QPACK_FIELDLINE_H

#include "common/bytes/span/span.h"

/* RFC 9204 4.5.2. Indexed Field Line: pattern 1Tiiiiii, where T=1 selects the
 * static table and the index is a 6-bit prefixed integer. The dynamic table
 * (T=0) is encoded identically; is_static carries T. */

/* Encode index/is_static as an indexed field line into buf.
 * Returns bytes written, or 0 if it does not fit. */
usz quic_qpack_indexed_encode(quic_mspan buf, u64 index, int is_static);

/* Decode an indexed field line from buf into *index and *is_static.
 * Returns bytes consumed, or 0 on a non-indexed pattern or truncation. */
usz quic_qpack_indexed_decode(quic_span buf, u64* index, int* is_static);

#endif
