#ifndef QUIC_QPACK_DYNGET_H
#define QUIC_QPACK_DYNGET_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 3.2.4. Resolve an absolute index to its live entry. Returns 1 and
 * fills *out with borrowed name/value views if the index is currently present,
 * 0 if it was never inserted or has been evicted. */
int quic_qpack_dyn_get(
    const quic_qpack_dyn* t, u64 abs_index, quic_qpack_field* out);

#endif
