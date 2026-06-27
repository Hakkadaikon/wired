#ifndef QUIC_H3_FIELDSIZE_H
#define QUIC_H3_FIELDSIZE_H

#include "sys/syscall.h"

/* RFC 9114 4.2.2: a field section larger than SETTINGS_MAX_FIELD_SECTION_SIZE
 * is an H3_MESSAGE_ERROR. A max of 0 means the limit is unset (unlimited). */

/* Whether a field section of `size` is within `max_size` (0 = unlimited). */
int quic_h3_field_section_ok(u64 size, u64 max_size);

#endif
