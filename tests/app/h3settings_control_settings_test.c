#include "test.h"

/* RFC 9114 6.2.1: control stream opens with type 0x00 then a SETTINGS frame
 * that satisfies the "first frame MUST be SETTINGS" rule. */
void test_h3settings_control_settings(void) {
  u8  buf[64];
  usz n = 0;
  CHECK(quic_h3settings_control_stream(buf, sizeof(buf), &n) == 1);

  /* leading stream type is control */
  u64 stype;
  usz consumed = 0;
  CHECK(
      quic_h3_stream_type_parse(quic_span_of(buf, n), &stype, &consumed) == 1);
  CHECK(consumed == 1 && quic_h3_stream_type_is_control(stype));

  /* the bytes after the type are a SETTINGS frame */
  quic_h3_frame f;
  usz r = quic_h3_frame_get(quic_span_of(buf + consumed, n - consumed), &f);
  CHECK(r == n - consumed && f.type == QUIC_H3_FRAME_SETTINGS);

  /* the first control frame passes the settings-sequence gate */
  quic_h3_settings_state st = {0};
  CHECK(quic_h3_settings_first(&st, f.type) == 1);

  /* no room */
  CHECK(quic_h3settings_control_stream(buf, 1, &n) == 0);
}

/* RFC 9220 3: the server's control stream advertises Extended CONNECT. */
/* RFC 9220 3: no request handler validates/processes :protocol yet
 * (quic_h3_connect_protocol_ok is unwired), so the server must not advertise
 * a capability it does not implement. */
void test_h3settings_control_settings_no_connect_protocol_yet(void) {
  u8  buf[64];
  usz n        = 0;
  usz consumed = 0;
  CHECK(quic_h3settings_control_stream(buf, sizeof(buf), &n) == 1);
  quic_h3_stream_type_parse(quic_span_of(buf, n), &(u64){0}, &consumed);

  quic_h3_frame f;
  quic_h3_frame_get(quic_span_of(buf + consumed, n - consumed), &f);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf + consumed, n - consumed, &s);
  CHECK(sr > 0);

  int found = 0;
  for (usz i = 0; i < s.n; i++)
    if (s.pairs[i].id == QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL) found = 1;
  CHECK(found == 0);
}
