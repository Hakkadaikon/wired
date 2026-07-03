#ifndef QUIC_H3SETTINGS_SETTINGS_BUILD_H
#define QUIC_H3SETTINGS_SETTINGS_BUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* The three common HTTP/3 + QPACK settings values to encode. */
typedef struct {
  u64 max_field_section_size;
  u64 qpack_max_table_capacity;
  u64 qpack_blocked_streams;
} quic_h3settings_in;

/* RFC 9114 7.2.4: build a SETTINGS frame carrying the three common settings
 * (MAX_FIELD_SECTION_SIZE 0x06, QPACK_MAX_TABLE_CAPACITY 0x01,
 * QPACK_BLOCKED_STREAMS 0x07). Returns 1 ok with out->len set, 0 if no room. */
int quic_h3settings_build(const quic_h3settings_in *in, quic_obuf *out);

#endif
