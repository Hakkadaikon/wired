#ifndef QUIC_ASN1_DERSEQ_H
#define QUIC_ASN1_DERSEQ_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* X.690 8.9. Cursor over the elements inside a SEQUENCE value. */

typedef struct {
  const u8 *p;
  usz       off;
  usz       len;
} quic_derseq;

/* Init over a SEQUENCE value (the bytes after its tag+length). */
void quic_derseq_init(quic_derseq *c, quic_span seq);

/* Read the next element. Sets *tag, *val and advances the cursor.
 * Returns 1 ok, 0 at end or on a malformed element. */
int quic_derseq_next(quic_derseq *c, u8 *tag, quic_span *val);

/* Read the next element, requiring tag want. Returns 1 ok, 0 otherwise. */
int quic_derseq_next_tagged(quic_derseq *c, u8 want, quic_span *val);

/* Advance the cursor past n elements. Returns 1 if all were present. */
int quic_derseq_skip(quic_derseq *c, usz n);

#endif
