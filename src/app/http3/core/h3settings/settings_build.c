#include "app/http3/core/h3settings/settings_build.h"

#include "app/http3/core/h3/frame.h" /* quic_h3_settings, quic_h3_settings_put, QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE */

/* RFC 9204 5: QPACK SETTINGS identifiers. */
#define QPACK_MAX_TABLE_CAPACITY 0x01
#define QPACK_BLOCKED_STREAMS 0x07

/* RFC 9114 7.2.4 */
int quic_h3settings_build(
    u64  max_field_section_size,
    u64  qpack_max_table_capacity,
    u64  qpack_blocked_streams,
    u8  *out,
    usz  cap,
    usz *out_len) {
  quic_h3_settings s;
  s.n              = 3;
  s.pairs[0].id    = QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE;
  s.pairs[0].value = max_field_section_size;
  s.pairs[1].id    = QPACK_MAX_TABLE_CAPACITY;
  s.pairs[1].value = qpack_max_table_capacity;
  s.pairs[2].id    = QPACK_BLOCKED_STREAMS;
  s.pairs[2].value = qpack_blocked_streams;

  usz w = quic_h3_settings_put(out, cap, &s);
  if (w == 0) return 0;
  *out_len = w;
  return 1;
}
