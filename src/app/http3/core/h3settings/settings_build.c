#include "app/http3/core/h3settings/settings_build.h"

#include "app/http3/core/h3/frame.h" /* quic_h3_settings, quic_h3_settings_put, QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE */
#include "app/http3/core/h3/qpack_settings.h" /* QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL */

/* RFC 9204 5: QPACK SETTINGS identifiers. */
#define QPACK_MAX_TABLE_CAPACITY 0x01
#define QPACK_BLOCKED_STREAMS 0x07

/* RFC 9220 3: append SETTINGS_ENABLE_CONNECT_PROTOCOL when requested. */
static void append_connect_protocol(
    const quic_h3settings_in* in, quic_h3_settings* s) {
  if (!in->enable_connect_protocol) return;
  s->pairs[s->n].id    = QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL;
  s->pairs[s->n].value = 1;
  s->n++;
}

/* RFC 9114 7.2.4 */
int quic_h3settings_build(const quic_h3settings_in* in, quic_obuf* out) {
  quic_h3_settings s;
  s.n              = 3;
  s.pairs[0].id    = QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE;
  s.pairs[0].value = in->max_field_section_size;
  s.pairs[1].id    = QPACK_MAX_TABLE_CAPACITY;
  s.pairs[1].value = in->qpack_max_table_capacity;
  s.pairs[2].id    = QPACK_BLOCKED_STREAMS;
  s.pairs[2].value = in->qpack_blocked_streams;
  append_connect_protocol(in, &s);

  usz w = quic_h3_settings_put(out->p, out->cap, &s);
  if (w == 0) return 0;
  out->len = w;
  return 1;
}
