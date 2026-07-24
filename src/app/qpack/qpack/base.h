#ifndef QUIC_QPACK_BASE_H
#define QUIC_QPACK_BASE_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 4.5.1.2. Base derives from the Required Insert Count, the Sign bit,
 * and Delta Base: Base = (sign==0) ? ric + delta_base : ric - delta_base - 1.
 */
u64 quic_qpack_base(u64 ric, int sign, u64 delta_base);

/* RFC 9204 4.5.1.2: Base MUST NOT be negative. With Sign 1, Base is
 * ric - delta_base - 1, which is negative (invalid) exactly when
 * ric <= delta_base. Returns 1 if (sign, ric, delta_base) yields a valid
 * (non-negative) Base, 0 if the field block must be treated as invalid. */
int quic_qpack_base_valid(u64 ric, int sign, u64 delta_base);

#endif
