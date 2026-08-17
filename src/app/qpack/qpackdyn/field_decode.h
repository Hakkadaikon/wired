#ifndef QPACKDYN_FIELD_DECODE_H
#define QPACKDYN_FIELD_DECODE_H

#include "app/qpack/qpack/dyntable.h"

/** The context an Indexed Field Line is decoded against: the dynamic table,
 * the section's Base, and the field-section bytes from the current position. */
typedef struct {
  const qpack_dyn* table;
  u64              base;
  wired_span       fs;
} qdyn_src;

/* RFC 9204 4.5.2 / 4.5.3. Decode one Indexed Field Line, or one Indexed Field
 * Line with Post-Base Index, at src->fs, resolving it to a borrowed
 * (name, value). A static reference (T=1) is resolved from the static table;
 * a dynamic relative reference (T=0) converts its relative index against
 * src->base to an absolute index; a post-Base reference converts its
 * post-Base index against src->base instead. Both dynamic forms resolve from
 * src->table. Returns 1 with *out filled and *consumed set, or 0 on a
 * non-matching pattern, truncation, or an index that resolves to no live
 * entry. */
int qdyn_decode_field(const qdyn_src* src, qpack_field* out, usz* consumed);

/* RFC 9204 4.5.5 / 3.2.6. Resolve a post-Base index against src->base to the
 * dynamic table entry's name only, converting the post-Base index to an
 * absolute index first. Returns 1 with *name filled, 0 if no live entry
 * resolves. Pair with qpack_literal_postbase_decode, which parses the
 * post-Base index and the literal value; only the name comes from the table.
 */
int qdyn_resolve_postbase_name(
    const qdyn_src* src, u64 postbase, wired_span* name);

#endif
