#ifndef H3SETTINGS_SETTINGS_BUILD_H
#define H3SETTINGS_SETTINGS_BUILD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** The common HTTP/3 + QPACK settings values to encode. */
typedef struct {
  /** RFC 9114 7.2.4.1: SETTINGS_MAX_FIELD_SECTION_SIZE value. */
  u64 max_field_section_size;
  /** RFC 9204 5: SETTINGS_QPACK_MAX_TABLE_CAPACITY value. */
  u64 qpack_max_table_capacity;
  /** RFC 9204 5: SETTINGS_QPACK_BLOCKED_STREAMS value. */
  u64 qpack_blocked_streams;
  /** RFC 9220 3: non-zero appends the 0x08
   * SETTINGS_ENABLE_CONNECT_PROTOCOL pair. */
  u64 enable_connect_protocol;
  /** RFC 9297 2.1.1: non-zero appends the 0x33 SETTINGS_H3_DATAGRAM pair
   * (value must be 0 or 1). */
  u64 enable_h3_datagram;
  /** draft-ietf-webtrans-http3 8.2: non-zero appends the 0xc671706a
   * SETTINGS_WEBTRANSPORT_MAX_SESSIONS pair carrying this value -- the
   * identifier browsers key WebTransport support on. */
  u64 wt_max_sessions;
  /** RFC 9114 7.2.4.1 / 9114-064: non-zero appends this reserved (grease,
   * 0x1f*N + 0x21 form, see h3_grease_value) identifier with value 0. The
   * probabilistic decision of whether/which to send belongs to the caller,
   * not this builder (0 = the pre-existing deterministic behavior every
   * caller keeps by default). */
  u64 grease_id;
  /** draft-ietf-webtrans-http3-15 5.5.1: non-zero appends the 0x2b64
   * SETTINGS_WT_INITIAL_MAX_STREAMS_UNI pair carrying this value -- the
   * initial WT_MAX_STREAMS(uni) limit, same semantics as
   * wired_wt_session_set_max_streams's bidi=0 case (session.h). */
  u64 wt_initial_max_streams_uni;
  /** draft-ietf-webtrans-http3-15 5.5.2: non-zero appends the 0x2b65
   * SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI pair, the bidi counterpart of
   * wt_initial_max_streams_uni. */
  u64 wt_initial_max_streams_bidi;
  /** draft-ietf-webtrans-http3-15 5.5.3: non-zero appends the 0x2b61
   * SETTINGS_WT_INITIAL_MAX_DATA pair -- the initial WT_MAX_DATA limit,
   * same semantics as wired_wt_session_set_max_data (session.h). */
  u64 wt_initial_max_data;
} h3settings_in;

/* RFC 9114 7.2.4: build a SETTINGS frame carrying the three common settings
 * (MAX_FIELD_SECTION_SIZE 0x06, QPACK_MAX_TABLE_CAPACITY 0x01,
 * QPACK_BLOCKED_STREAMS 0x07), plus SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 9220
 * 3, id 0x08) when in->enable_connect_protocol is non-zero, SETTINGS_H3_
 * DATAGRAM (RFC 9297 2.1.1, id 0x33) when in->enable_h3_datagram is non-zero,
 * and SETTINGS_WEBTRANSPORT_MAX_SESSIONS (draft-ietf-webtrans-http3 8.2, id
 * 0xc671706a) when in->wt_max_sessions is non-zero. Returns 1 ok with
 * out->len set, 0 if no room. */
int h3settings_build(const h3settings_in* in, wired_obuf* out);

#endif
