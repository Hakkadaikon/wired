#ifndef QPACK_BASE_H
#define QPACK_BASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5.1.2. Base derives from the Required Insert Count, the Sign bit,
 * and Delta Base: Base = (sign==0) ? ric + delta_base : ric - delta_base - 1.
 */
u64 qpack_base(u64 ric, int sign, u64 delta_base);

/* RFC 9204 4.5.1.2: Base MUST NOT be negative. With Sign 1, Base is
 * ric - delta_base - 1, which is negative (invalid) exactly when
 * ric <= delta_base. With Sign 0, ric + delta_base past 2^64-1 wraps and is
 * likewise invalid. Returns 1 if (sign, ric, delta_base) yields a valid
 * Base, 0 if the field block must be treated as invalid -- callers only
 * compute qpack_base after this returns 1. */
int qpack_base_valid(u64 ric, int sign, u64 delta_base);

#endif
