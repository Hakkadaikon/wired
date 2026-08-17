#ifndef QUIC_ASN1_DERSEQ_H
#define QUIC_ASN1_DERSEQ_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* X.690 8.9. Cursor over the elements inside a SEQUENCE value. */

/** Cursor state: p is the SEQUENCE value's start, off the current read
 * position, len its total byte length. */
typedef struct {
  const u8* p;
  usz       off;
  usz       len;
} derseq;

/* Init over a SEQUENCE value (the bytes after its tag+length). */
void derseq_init(derseq* c, wired_span seq);

/* Read the next element. Sets *tag, *val and advances the cursor.
 * Returns 1 ok, 0 at end or on a malformed element. */
int derseq_next(derseq* c, u8* tag, wired_span* val);

/* Read the next element, requiring tag want. Returns 1 ok, 0 otherwise. */
int derseq_next_tagged(derseq* c, u8 want, wired_span* val);

/* Advance the cursor past n elements. Returns 1 if all were present. */
int derseq_skip(derseq* c, usz n);

#endif
