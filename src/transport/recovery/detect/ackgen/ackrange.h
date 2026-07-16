#ifndef QUIC_ACKGEN_ACKRANGE_H
#define QUIC_ACKGEN_ACKRANGE_H

#include "common/platform/sys/syscall.h"

/** A read-only view of a u64 array. */
typedef struct {
  const u64* p; /**< pointer to the first element */
  usz        n; /**< element count */
} quic_u64view;

/** A fixed-capacity u64 output buffer; the callee fills *len. */
typedef struct {
  u64* p;   /**< destination buffer */
  usz  cap; /**< capacity in elements */
  usz  len; /**< out: elements actually written */
} quic_u64obuf;

/* RFC 9000 19.3: an ACK frame reports the Largest Acknowledged packet number
 * and a descending list of contiguous ranges separated by gaps. This builds
 * those ranges from an ascending, deduplicated array of received packet
 * numbers (received_pns).
 *
 * Output layout (descending, matching wire order), written into ranges->p:
 *   largest          = highest received packet number
 *   ranges->p[0]     = First ACK Range length (count-1 of the top block)
 *   ranges->p[2k-1]  = Gap to the next block (RFC 19.3.1 encoding)
 *   ranges->p[2k]    = ACK Range Length of block k (count-1)
 *   ranges->len      = number of u64 values written
 *
 * ranges->cap bounds the write. Returns 1 on success, 0 if received_pns is
 * empty or ranges->cap is too small. */
int quic_ackgen_build_ranges(
    quic_u64view received_pns, u64* largest, quic_u64obuf* ranges);

#endif
