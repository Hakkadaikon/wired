#include "app/http3/core/h3settings/settings_build.h"

#include "app/http3/core/h3/frame.h" /* quic_h3_settings, quic_h3_settings_put, QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE */
#include "app/http3/core/h3/qpack_settings.h" /* QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL */

/* RFC 9204 5: QPACK SETTINGS identifiers. */
#define QPACK_MAX_TABLE_CAPACITY 0x01
#define QPACK_BLOCKED_STREAMS 0x07

/* RFC 9297 2.1.1. */
#define QUIC_H3_SETTINGS_H3_DATAGRAM 0x33
/* draft-ietf-webtrans-http3 8.2 SETTINGS_WEBTRANSPORT_MAX_SESSIONS (quiche's
 * SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07) -- the identifier current-draft
 * peers key WebTransport support on. */
#define QUIC_H3_SETTINGS_WT_MAX_SESSIONS 0xc671706a
/* draft-ietf-webtrans-http3-02 SETTINGS_ENABLE_WEBTRANSPORT (quiche's
 * SETTINGS_WEBTRANS_DRAFT00). Chrome negotiates WebTransport only when this
 * draft-02 pair is present in addition to the draft-07 identifier, so both
 * generations are advertised together. */
#define QUIC_H3_SETTINGS_WT_DRAFT02 0x2b603742
/* draft-ietf-webtrans-http3-15 3.1 SETTINGS_WT_ENABLED. webtransport-go's
 * client requires this exact identifier to be non-zero and accepts neither
 * the draft-07 max-sessions pair nor the draft-02 pair in its place, so all
 * three generations go out together. */
#define QUIC_H3_SETTINGS_WT_ENABLED 0x2c7cf000

/* RFC 9220 3: append SETTINGS_ENABLE_CONNECT_PROTOCOL when requested. */
static void append_connect_protocol(
    const quic_h3settings_in* in, quic_h3_settings* s) {
  if (!in->enable_connect_protocol) return;
  s->pairs[s->n].id    = QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL;
  s->pairs[s->n].value = 1;
  s->n++;
}

/* RFC 9297 2.1.1: append SETTINGS_H3_DATAGRAM when requested. */
static void append_h3_datagram(
    const quic_h3settings_in* in, quic_h3_settings* s) {
  if (!in->enable_h3_datagram) return;
  s->pairs[s->n].id    = QUIC_H3_SETTINGS_H3_DATAGRAM;
  s->pairs[s->n].value = 1;
  s->n++;
}

/* draft-ietf-webtrans-http3 8.2 + draft-02: append both generations'
 * WebTransport settings when requested (see QUIC_H3_SETTINGS_WT_DRAFT02's
 * doc for why the legacy pair is still required). */
static void append_wt_max_sessions(
    const quic_h3settings_in* in, quic_h3_settings* s) {
  if (!in->wt_max_sessions) return;
  s->pairs[s->n].id    = QUIC_H3_SETTINGS_WT_MAX_SESSIONS;
  s->pairs[s->n].value = in->wt_max_sessions;
  s->n++;
  s->pairs[s->n].id    = QUIC_H3_SETTINGS_WT_DRAFT02;
  s->pairs[s->n].value = 1;
  s->n++;
  s->pairs[s->n].id    = QUIC_H3_SETTINGS_WT_ENABLED;
  s->pairs[s->n].value = 1;
  s->n++;
}

/* RFC 9114 7.2.4.1 / 9114-064: append a caller-chosen reserved (grease)
 * SETTINGS identifier when in->grease_id is non-zero -- the probabilistic
 * decision of WHETHER and WHICH identifier to send lives in the caller
 * (quic_h3settings_control_stream), keeping this function itself
 * deterministic and easy to test byte-for-byte. */
static void append_grease(const quic_h3settings_in* in, quic_h3_settings* s) {
  if (!in->grease_id) return;
  s->pairs[s->n].id    = in->grease_id;
  s->pairs[s->n].value = 0;
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
  append_h3_datagram(in, &s);
  append_wt_max_sessions(in, &s);
  append_grease(in, &s);

  usz w = quic_h3_settings_put(out->p, out->cap, &s);
  if (w == 0) return 0;
  out->len = w;
  return 1;
}
