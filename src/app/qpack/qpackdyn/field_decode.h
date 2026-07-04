#ifndef QUIC_QPACKDYN_FIELD_DECODE_H
#define QUIC_QPACKDYN_FIELD_DECODE_H

#include "app/qpack/qpack/dyntable.h"

/* The context an Indexed Field Line is decoded against: the dynamic table,
 * the section's Base, and the field-section bytes from the current position. */
typedef struct {
  const quic_qpack_dyn* table;
  u64                   base;
  quic_span             fs;
} quic_qdyn_src;

/* RFC 9204 4.5. Decode one Indexed Field Line at src->fs, resolving it to a
 * borrowed (name, value). A static reference (T=1) is resolved from the static
 * table; a dynamic reference (T=0) converts its relative index against
 * src->base to an absolute index and resolves it from src->table. Returns 1
 * with *out filled and *consumed set, or 0 on a non-indexed pattern,
 * truncation, or an index that resolves to no live entry. */
int quic_qdyn_decode_field(
    const quic_qdyn_src* src, quic_qpack_field* out, usz* consumed);

#endif
