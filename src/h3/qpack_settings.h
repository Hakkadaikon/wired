#ifndef QUIC_H3_QPACK_SETTINGS_H
#define QUIC_H3_QPACK_SETTINGS_H

#include "sys/syscall.h"

/* RFC 9204 5. QPACK SETTINGS parameters carried in the HTTP/3 SETTINGS frame. */
#define QUIC_H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY 0x01
#define QUIC_H3_SETTINGS_QPACK_BLOCKED_STREAMS    0x07

/* Effective value of a received QPACK setting. When the SETTINGS frame omits
 * the parameter the default of 0 applies (no dynamic table / no blocked
 * streams), so callers pass 0 in that case and the value is returned as-is. */
u64 quic_h3_qpack_max_table(u64 setting_value);
u64 quic_h3_qpack_blocked_streams(u64 setting_value);

#endif
