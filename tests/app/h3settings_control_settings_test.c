#include "test.h"

/* RFC 9114 6.2.1: control stream opens with type 0x00 then a SETTINGS frame
 * that satisfies the "first frame MUST be SETTINGS" rule. */
void test_h3settings_control_settings(void) {
  u8  buf[64];
  usz n = 0;
  CHECK(quic_h3settings_control_stream(0, buf, sizeof(buf), &n) == 1);

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
  CHECK(quic_h3settings_control_stream(0, buf, 1, &n) == 0);
}

/* RFC 9220 3: the server's control stream advertises Extended CONNECT — the
 * request path now validates :protocol before establishing a WebTransport
 * session (srvrun_is_wt_connect), so it is safe to advertise support. */
void test_h3settings_control_settings_advertises_connect_protocol(void) {
  u8  buf[64];
  usz n        = 0;
  usz consumed = 0;
  CHECK(quic_h3settings_control_stream(0, buf, sizeof(buf), &n) == 1);
  quic_h3_stream_type_parse(quic_span_of(buf, n), &(u64){0}, &consumed);

  quic_h3_frame f;
  quic_h3_frame_get(quic_span_of(buf + consumed, n - consumed), &f);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf + consumed, n - consumed, &s);
  CHECK(sr > 0);

  int found = 0;
  for (usz i = 0; i < s.n; i++)
    if (s.pairs[i].id == QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL) found = 1;
  CHECK(found == 1);
}

/* 1 if the parsed SETTINGS carry the (id, value) pair. */
static int hcs_has_pair(const quic_h3_settings* s, u64 id, u64 value) {
  for (usz i = 0; i < s->n; i++)
    if (s->pairs[i].id == id && s->pairs[i].value == value) return 1;
  return 0;
}

/* RFC 9297 2.1.1 / draft-ietf-webtrans-http3 8.2: with advertise_wt the
 * control stream's SETTINGS carry SETTINGS_H3_DATAGRAM=1 and
 * SETTINGS_WEBTRANSPORT_MAX_SESSIONS>=1 -- the pair a browser requires
 * before it will open a WebTransport session (their absence surfaces as
 * ERR_METHOD_NOT_SUPPORTED); without it neither appears. */
void test_h3settings_control_settings_advertises_wt(void) {
  u8               buf[64];
  usz              n        = 0;
  usz              consumed = 0;
  quic_h3_settings s;

  CHECK(quic_h3settings_control_stream(1, buf, sizeof(buf), &n) == 1);
  quic_h3_stream_type_parse(quic_span_of(buf, n), &(u64){0}, &consumed);
  CHECK(quic_h3_settings_get(buf + consumed, n - consumed, &s) > 0);
  CHECK(hcs_has_pair(&s, 0x33, 1) == 1);
  CHECK(hcs_has_pair(&s, 0xc671706a, 1) == 1);
  CHECK(hcs_has_pair(&s, 0x2b603742, 1) == 1);
  CHECK(hcs_has_pair(&s, 0x2c7cf000, 1) == 1);

  CHECK(quic_h3settings_control_stream(0, buf, sizeof(buf), &n) == 1);
  quic_h3_stream_type_parse(quic_span_of(buf, n), &(u64){0}, &consumed);
  CHECK(quic_h3_settings_get(buf + consumed, n - consumed, &s) > 0);
  CHECK(hcs_has_pair(&s, 0x33, 1) == 0);
  CHECK(hcs_has_pair(&s, 0xc671706a, 1) == 0);
  CHECK(hcs_has_pair(&s, 0x2b603742, 1) == 0);
  CHECK(hcs_has_pair(&s, 0x2c7cf000, 1) == 0);
}
