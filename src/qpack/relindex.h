#ifndef QUIC_QPACK_RELINDEX_H
#define QUIC_QPACK_RELINDEX_H

#include "sys/syscall.h"

/* RFC 9204 3.2.5. A relative index in a field section counts back from Base:
 * the absolute index is base - rel - 1. */
u64 quic_qpack_rel_to_abs(u64 base, u64 rel);

/* RFC 9204 3.2.6. A post-base index counts forward from Base: the absolute
 * index is base + postbase. */
u64 quic_qpack_postbase_to_abs(u64 base, u64 postbase);

#endif
