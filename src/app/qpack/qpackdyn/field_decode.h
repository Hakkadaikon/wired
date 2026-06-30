#ifndef QUIC_QPACKDYN_FIELD_DECODE_H
#define QUIC_QPACKDYN_FIELD_DECODE_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 4.5. Decode one Indexed Field Line at fs+pos, resolving it to a
 * borrowed (name, value). A static reference (T=1) is resolved from the static
 * table; a dynamic reference (T=0) converts its relative index against base to
 * an absolute index and resolves it from the dynamic table. Returns 1 with the
 * borrowed pointers and *consumed set, or 0 on a non-indexed pattern,
 * truncation, or an index that resolves to no live entry. */
int quic_qdyn_decode_field(
    const quic_qpack_dyn *table,
    u64                   base,
    const u8             *fs,
    usz                   fs_len,
    usz                   pos,
    const u8            **name,
    usz                  *name_len,
    const u8            **value,
    usz                  *value_len,
    usz                  *consumed);

#endif
