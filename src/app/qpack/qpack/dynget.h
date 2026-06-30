#ifndef QUIC_QPACK_DYNGET_H
#define QUIC_QPACK_DYNGET_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 3.2.4. Resolve an absolute index to its live entry. Returns 1 and
 * sets the borrowed name/value pointers if the index is currently present,
 * 0 if it was never inserted or has been evicted. */
int quic_qpack_dyn_get(
    const quic_qpack_dyn *t,
    u64                   abs_index,
    const u8            **name,
    usz                  *name_len,
    const u8            **value,
    usz                  *value_len);

#endif
