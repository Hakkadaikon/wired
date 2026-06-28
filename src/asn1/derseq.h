#ifndef QUIC_ASN1_DERSEQ_H
#define QUIC_ASN1_DERSEQ_H

#include "sys/syscall.h"

/* X.690 8.9. Cursor over the elements inside a SEQUENCE value. */

typedef struct {
    const u8 *p;
    usz off;
    usz len;
} quic_derseq;

/* Init over a SEQUENCE value (the bytes after its tag+length). */
void quic_derseq_init(quic_derseq *c, const u8 *seq_val, usz seq_len);

/* Read the next element. Sets *tag, *val, *val_len and advances the cursor.
 * Returns 1 ok, 0 at end or on a malformed element. */
int quic_derseq_next(quic_derseq *c, u8 *tag, const u8 **val, usz *val_len);

#endif
