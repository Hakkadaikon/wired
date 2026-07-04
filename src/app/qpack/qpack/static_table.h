#ifndef QUIC_QPACK_STATIC_TABLE_H
#define QUIC_QPACK_STATIC_TABLE_H

#include "common/platform/sys/syscall.h"

/* RFC 9204 Appendix A. The QPACK static table: 99 fixed (name, value)
 * entries at indices 0..98. Names and values are NUL-terminated C strings
 * (an empty value is ""). */

#define QUIC_QPACK_STATIC_COUNT 99

/* Look up entry `index`, storing its name and value. Returns 1 ok, 0 if
 * index is out of range. */
int quic_qpack_static_get(usz index, const char** name, const char** value);

/* Find the index whose name and value both match exactly. Returns the index,
 * or -1 if none matches. */
i64 quic_qpack_static_find(const char* name, const char* value);

#endif
