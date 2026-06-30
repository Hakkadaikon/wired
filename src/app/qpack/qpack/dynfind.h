#ifndef QUIC_QPACK_DYNFIND_H
#define QUIC_QPACK_DYNFIND_H

#include "app/qpack/qpack/dyntable.h"

/* RFC 9204 2.1. Search live entries for one matching name (and value when
 * possible). A name+value match is preferred over a name-only match. On a
 * hit, *abs_index gets the entry's absolute index, *value_matched is 1 for a
 * full match or 0 for name-only, and the call returns 1. Returns 0 if no
 * entry's name matches. */
int quic_qpack_dyn_find(
    const quic_qpack_dyn *t,
    const u8             *name,
    usz                   name_len,
    const u8             *value,
    usz                   value_len,
    u64                  *abs_index,
    int                  *value_matched);

#endif
