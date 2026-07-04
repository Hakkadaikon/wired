#ifndef QUIC_QPACK_DYNFIND_H
#define QUIC_QPACK_DYNFIND_H

#include "app/qpack/qpack/dyntable.h"

/* A search hit: the entry's absolute index and whether the value matched. */
typedef struct {
  u64 abs_index;
  int value_matched; /* 1 = name+value, 0 = name only */
} quic_qpack_match;

/* RFC 9204 2.1. Search live entries for one matching f->name (and f->value
 * when possible). A name+value match is preferred over a name-only match. On
 * a hit, fills *m and returns 1. Returns 0 if no entry's name matches. */
int quic_qpack_dyn_find(
    const quic_qpack_dyn* t, const quic_qpack_field* f, quic_qpack_match* m);

#endif
