#ifndef QUIC_H3SETTINGS_SETTINGS_BUILD_H
#define QUIC_H3SETTINGS_SETTINGS_BUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* The common HTTP/3 + QPACK settings values to encode. */
typedef struct {
  u64 max_field_section_size;
  u64 qpack_max_table_capacity;
  u64 qpack_blocked_streams;
  u64 enable_connect_protocol; /* RFC 9220 3: non-zero appends the 0x08
                                  SETTINGS_ENABLE_CONNECT_PROTOCOL pair */
  u64 enable_h3_datagram;      /* RFC 9297 2.1.1: non-zero appends the 0x33
                                   SETTINGS_H3_DATAGRAM pair (value must be
                                   0 or 1) */
  u64 wt_max_sessions;         /* draft-ietf-webtrans-http3 8.2: non-zero
                                   appends the 0xc671706a
                                   SETTINGS_WEBTRANSPORT_MAX_SESSIONS pair
                                   carrying this value -- the identifier
                                   browsers key WebTransport support on */
} quic_h3settings_in;

/* RFC 9114 7.2.4: build a SETTINGS frame carrying the three common settings
 * (MAX_FIELD_SECTION_SIZE 0x06, QPACK_MAX_TABLE_CAPACITY 0x01,
 * QPACK_BLOCKED_STREAMS 0x07), plus SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220
 * 3, id 0x08) when in->enable_connect_protocol is non-zero, SETTINGS_H3_
 * DATAGRAM (RFC 9297 2.1.1, id 0x33) when in->enable_h3_datagram is non-zero,
 * and SETTINGS_WEBTRANSPORT_MAX_SESSIONS (draft-ietf-webtrans-http3 8.2, id
 * 0xc671706a) when in->wt_max_sessions is non-zero. Returns 1 ok with
 * out->len set, 0 if no room. */
int quic_h3settings_build(const quic_h3settings_in* in, quic_obuf* out);

#endif
