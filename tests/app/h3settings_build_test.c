#include "test.h"

/* RFC 9114 7.2.4: SETTINGS frame wire structure and round-trip. */
void test_h3settings_build(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 0};
  quic_obuf          ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);
  usz n = ob.len;
  CHECK(n > 2 && buf[0] == QUIC_H3_FRAME_SETTINGS);

  /* length field matches the remaining payload bytes */
  quic_h3_frame f;
  usz           r = quic_h3_frame_get(quic_span_of(buf, n), &f);
  CHECK(r == n && f.type == QUIC_H3_FRAME_SETTINGS && f.payload_len == n - 2);

  /* read the (id,value) pairs back via the existing SETTINGS codec */
  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, n, &s);
  CHECK(sr == n && s.n == 3);
  CHECK(
      s.pairs[0].id == QUIC_H3_SETTINGS_MAX_FIELD_SECTION_SIZE &&
      s.pairs[0].value == 0x4000);
  CHECK(s.pairs[1].id == 0x01 && s.pairs[1].value == 0);
  CHECK(s.pairs[2].id == 0x07 && s.pairs[2].value == 100);

  /* no room */
  ob = (quic_obuf){buf, 2, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 0);
}

/* RFC 9220 3: enable_connect_protocol!=0 appends SETTINGS_ENABLE_CONNECT_
 * PROTOCOL (0x08)=1 as a 4th pair; omitted (0) keeps the 3-pair wire form. */
void test_h3settings_build_connect_protocol(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 1};
  quic_obuf          ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 4);
  CHECK(
      s.pairs[3].id == QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL &&
      s.pairs[3].value == 1);
}
