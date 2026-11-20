#ifndef QPACK_RELINDEX_H
#define QPACK_RELINDEX_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 3.2.5. A relative index in a field section counts back from Base:
 * the absolute index is base - rel - 1. Returns 1 with *abs filled, 0 if
 * rel >= base -- the reference points below absolute index 0 and the section
 * is invalid (QPACK_DECOMPRESSION_FAILED at the caller). */
int qpack_rel_to_abs(u64 base, u64 rel, u64* abs);

/* RFC 9204 3.2.6. A post-base index counts forward from Base: the absolute
 * index is base + postbase. Returns 1 with *abs filled, 0 if the sum passes
 * 2^64-1 -- a wrapped index could alias a live low entry, so the section is
 * invalid (QPACK_DECOMPRESSION_FAILED at the caller). */
int qpack_postbase_to_abs(u64 base, u64 postbase, u64* abs);

#endif
