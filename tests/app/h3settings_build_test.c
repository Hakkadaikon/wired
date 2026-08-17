#include "test.h"

/* RFC 9114 7.2.4: SETTINGS frame wire structure and round-trip. */
void test_h3settings_build(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 0, 0, 0, 0, 0, 0, 0};
  wired_obuf         ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);
  usz n = ob.len;
  CHECK(n > 2 && buf[0] == QUIC_H3_FRAME_SETTINGS);

  /* length field matches the remaining payload bytes */
  quic_h3_frame f;
  usz           r = quic_h3_frame_get(wired_span_of(buf, n), &f);
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
  ob = (wired_obuf){buf, 2, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 0);
}

/* RFC 9220 3: enable_connect_protocol!=0 appends SETTINGS_ENABLE_CONNECT_
 * PROTOCOL (0x08)=1 as a 4th pair; omitted (0) keeps the 3-pair wire form. */
void test_h3settings_build_connect_protocol(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 1, 0, 0, 0, 0, 0, 0};
  wired_obuf         ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 4);
  CHECK(
      s.pairs[3].id == QUIC_H3_SETTINGS_ENABLE_CONNECT_PROTOCOL &&
      s.pairs[3].value == 1);
}

/* RFC 9297 2.1.1 / draft-ietf-webtrans-http3 8.2: enable_h3_datagram and
 * wt_max_sessions each append their own SETTINGS pair when non-zero,
 * round-tripped through the existing SETTINGS decoder. The WebTransport
 * identifier must be 0xc671706a (SETTINGS_WEBTRANSPORT_MAX_SESSIONS) -- the
 * identifier Chrome's implementation keys on; anything else reads as "no
 * WebTransport support" and the browser refuses every session with
 * ERR_METHOD_NOT_SUPPORTED. */
void test_h3settings_build_h3_datagram_and_wt_enabled(void) {
  u8                 buf[48];
  quic_h3settings_in in = {0x4000, 0, 100, 0, 1, 5, 0, 0, 0, 0};
  wired_obuf         ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 7);
  CHECK(s.pairs[3].id == 0x33 && s.pairs[3].value == 1);
  CHECK(s.pairs[4].id == 0xc671706a && s.pairs[4].value == 5);
  /* draft-02 companion pair: Chrome 149 keys on this one (verified live) */
  CHECK(s.pairs[5].id == 0x2b603742 && s.pairs[5].value == 1);
  /* draft-15 SETTINGS_WT_ENABLED: webtransport-go's client keys on this
   * one and rejects the session without it (verified live) */
  CHECK(s.pairs[6].id == 0x2c7cf000 && s.pairs[6].value == 1);
}

/* Both flags at 0 (the default) keep the 3-pair wire form, matching the
 * pre-existing behavior exercised by test_h3settings_build. */
void test_h3settings_build_h3_datagram_and_wt_disabled(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 0, 0, 0, 0, 0, 0, 0};
  wired_obuf         ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 3);
}

/* RFC 9114 7.2.4.1 / 9114-064: grease_id == 0 (the default, every existing
 * caller above) keeps the exact pre-grease wire form -- adding the field
 * disturbs nothing already built on this function. */
void test_h3settings_build_grease_zero_omits_pair(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 0, 0, 0, 0, 0, 0, 0};
  wired_obuf         ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 3);
}

/* A non-zero grease_id appends a 4th pair carrying exactly that identifier
 * with value 0, deterministically (the builder itself never rolls dice --
 * see control_settings.c for where the probability lives). */
void test_h3settings_build_grease_nonzero_appends_pair(void) {
  u8                 buf[32];
  u64                gid = quic_h3_grease_value(9);
  quic_h3settings_in in  = {0x4000, 0, 100, 0, 0, 0, gid, 0, 0, 0};
  wired_obuf         ob  = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 4);
  CHECK(s.pairs[3].id == gid && s.pairs[3].value == 0);
  CHECK(quic_h3_is_reserved(s.pairs[3].id) == 1);
}

/* draft-ietf-webtrans-http3-15 5.5.1/5.5.2/5.5.3 (WTH3-051): each of the
 * three WT flow-control initial-limit fields appends its own SETTINGS pair
 * when non-zero, with the exact identifiers the draft registers
 * (0x2b64/0x2b65/0x2b61), round-tripped through the existing decoder. */
void test_h3settings_build_wt_flow_control_initial_limits(void) {
  u8                 buf[64];
  quic_h3settings_in in = {
      .max_field_section_size      = 0x4000,
      .qpack_blocked_streams       = 100,
      .wt_initial_max_streams_uni  = 3,
      .wt_initial_max_streams_bidi = 7,
      .wt_initial_max_data         = 65536};
  wired_obuf ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 6);
  CHECK(s.pairs[3].id == 0x2b64 && s.pairs[3].value == 3);
  CHECK(s.pairs[4].id == 0x2b65 && s.pairs[4].value == 7);
  CHECK(s.pairs[5].id == 0x2b61 && s.pairs[5].value == 65536);
}

/* All three WT flow-control fields at 0 (the default) keep the 3-pair wire
 * form -- adding the fields disturbs nothing already built on this
 * function. */
void test_h3settings_build_wt_flow_control_zero_omits_pairs(void) {
  u8                 buf[32];
  quic_h3settings_in in = {0x4000, 0, 100, 0, 0, 0, 0, 0, 0, 0};
  wired_obuf         ob = {buf, sizeof buf, 0};
  CHECK(quic_h3settings_build(&in, &ob) == 1);

  quic_h3_settings s;
  usz              sr = quic_h3_settings_get(buf, ob.len, &s);
  CHECK(sr == ob.len && s.n == 3);
}
