#ifndef QPACK_DYNGET_H
#define QPACK_DYNGET_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 3.2.4. Resolve an absolute index to its live entry. Returns 1 and
 * fills *out with borrowed name/value views if the index is currently present,
 * 0 if it was never inserted or has been evicted. */
int qpack_dyn_get(const qpack_dyn* t, u64 abs_index, qpack_field* out);

/* RFC 9204 3.2.5 / 2.2.3. Resolve a relative index as used on the ENCODER
 * stream (Insert with Name Reference, Duplicate): relative index 0 is the
 * most recently inserted entry, i.e. the base is the table's next insertion
 * point (dropped + count). Returns 1 and fills *out if the referenced entry
 * is still live, 0 if it has already been evicted -- the caller treats 0 as a
 * connection error of type QPACK_ENCODER_STREAM_ERROR. */
int qpack_dyn_get_enc_rel(const qpack_dyn* t, u64 rel, qpack_field* out);

#endif
