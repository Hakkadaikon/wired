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
      quic_h3_stream_type_parse(wired_span_of(buf, n), &stype, &consumed) == 1);
  CHECK(consumed == 1 && quic_h3_stream_type_is_control(stype));

  /* the bytes after the type are a SETTINGS frame */
  quic_h3_frame f;
  usz r = quic_h3_frame_get(wired_span_of(buf + consumed, n - consumed), &f);
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
  quic_h3_stream_type_parse(wired_span_of(buf, n), &(u64){0}, &consumed);

  quic_h3_frame f;
  quic_h3_frame_get(wired_span_of(buf + consumed, n - consumed), &f);

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
  quic_h3_stream_type_parse(wired_span_of(buf, n), &(u64){0}, &consumed);
  CHECK(quic_h3_settings_get(buf + consumed, n - consumed, &s) > 0);
  CHECK(hcs_has_pair(&s, 0x33, 1) == 1);
  CHECK(hcs_has_pair(&s, 0xc671706a, 1) == 1);
  CHECK(hcs_has_pair(&s, 0x2b603742, 1) == 1);
  CHECK(hcs_has_pair(&s, 0x2c7cf000, 1) == 1);

  CHECK(quic_h3settings_control_stream(0, buf, sizeof(buf), &n) == 1);
  quic_h3_stream_type_parse(wired_span_of(buf, n), &(u64){0}, &consumed);
  CHECK(quic_h3_settings_get(buf + consumed, n - consumed, &s) > 0);
  CHECK(hcs_has_pair(&s, 0x33, 1) == 0);
  CHECK(hcs_has_pair(&s, 0xc671706a, 1) == 0);
  CHECK(hcs_has_pair(&s, 0x2b603742, 1) == 0);
  CHECK(hcs_has_pair(&s, 0x2c7cf000, 1) == 0);
}

/* RFC 9297 2.1.1 / 9297-014: "When servers decide to accept 0-RTT data, they
 * MUST send a SETTINGS_H3_DATAGRAM setting greater than or equal to the
 * value they sent to the client in the connection where they sent them the
 * NewSessionTicket message." A pure comparison predicate: the caller (which
 * owns whatever ticket-keyed memory of the prior value it has) supplies both
 * sides; this only judges monotonicity, mirroring zerortt_replay_ok's
 * own caller-resolves-the-inputs shape (zerortt_policy.h). */
void test_h3settings_h3_datagram_monotonic_ok(void) {
  CHECK(quic_h3settings_h3_datagram_monotonic_ok(0, 0) == 1); /* equal */
  CHECK(quic_h3settings_h3_datagram_monotonic_ok(1, 1) == 1); /* equal */
  CHECK(quic_h3settings_h3_datagram_monotonic_ok(0, 1) == 1); /* raised */
  CHECK(quic_h3settings_h3_datagram_monotonic_ok(1, 0) == 0); /* lowered */
}

/* RFC 9114 7.2.4.2 / 9114-066: identical settings are trivially compatible
 * (a client complying with prior cannot be violated by an identical
 * current). */
void test_h3settings_zerortt_compatible_identical_ok(void) {
  quic_h3settings_in s = {0x4000, 100, 4, 1, 1, 1, 0, 0, 0, 0};
  CHECK(quic_h3settings_zerortt_compatible(&s, &s) == 1);
}

/* Raising any single one of the six compatibility-relevant fields (all
 * except grease_id, which the client is required to ignore regardless of
 * value, RFC 9114 7.2.8) stays compatible. */
void test_h3settings_zerortt_compatible_raised_fields_ok(void) {
  quic_h3settings_in prior    = {0x4000, 100, 4, 1, 1, 1, 0, 0, 0, 0};
  quic_h3settings_in raised[] = {
      {0x8000, 100, 4, 1, 1, 1, 0, 0, 0, 0},
      {0x4000, 200, 4, 1, 1, 1, 0, 0, 0, 0},
      {0x4000, 100, 8, 1, 1, 1, 0, 0, 0, 0},
      {0x4000, 100, 4, 1, 1, 1, 0, 0, 0, 0},
      {0x4000, 100, 4, 1, 1, 2, 0, 0, 0, 0},
  };
  for (usz i = 0; i < sizeof raised / sizeof raised[0]; i++)
    CHECK(quic_h3settings_zerortt_compatible(&prior, &raised[i]) == 1);
}

/* draft-ietf-webtrans-http3-15/RFC 9297: withdrawing enable_h3_datagram
 * (1 -> 0) after the client relied on it MUST NOT be treated as
 * compatible -- this is the 9114-066 case the RFC text calls out by name
 * ("its SETTINGS frame MUST NOT reduce any limits"). */
void test_h3settings_zerortt_compatible_extension_withdrawn_rejected(void) {
  quic_h3settings_in prior   = {0x4000, 100, 4, 1, 1, 1, 0, 0, 0, 0};
  quic_h3settings_in current = {0x4000, 100, 4, 1, 0, 1, 0, 0, 0, 0};
  CHECK(quic_h3settings_zerortt_compatible(&prior, &current) == 0);
}

/* Lowering any single one of the three core limits (max_field_section_size,
 * qpack_max_table_capacity, qpack_blocked_streams) is incompatible. */
void test_h3settings_zerortt_compatible_lowered_core_limit_rejected(void) {
  quic_h3settings_in prior     = {0x4000, 100, 4, 1, 1, 1, 0, 0, 0, 0};
  quic_h3settings_in lowered[] = {
      {0x2000, 100, 4, 1, 1, 1, 0, 0, 0, 0},
      {0x4000, 50, 4, 1, 1, 1, 0, 0, 0, 0},
      {0x4000, 100, 2, 1, 1, 1, 0, 0, 0, 0},
  };
  for (usz i = 0; i < sizeof lowered / sizeof lowered[0]; i++)
    CHECK(quic_h3settings_zerortt_compatible(&prior, &lowered[i]) == 0);
}

/* draft-ietf-webtrans-http3-15 3.2 (WTH3-019): "if the server accepts
 * 0-RTT, the server shall not reduce the limit of maximum open
 * WebTransport sessions or other initial flow control values from those
 * negotiated during the previous session." wt_max_sessions is exactly
 * "the limit of maximum open WebTransport sessions"; wt_initial_max_
 * streams_uni/bidi and wt_initial_max_data are exactly the "other initial
 * flow control values" (draft 5.5's SETTINGS_WT_INITIAL_MAX_*) -- all
 * four already participate in quic_h3settings_zerortt_compatible's
 * general never-regress rule, so lowering any one of them alone is
 * rejected the same way the core/extension fields are above. */
void test_h3settings_zerortt_compatible_wt_session_limit_lowered_rejected(
    void) {
  quic_h3settings_in prior = {
      .max_field_section_size = 0x4000,
      .qpack_blocked_streams  = 100,
      .wt_max_sessions        = 4};
  quic_h3settings_in current = prior;
  current.wt_max_sessions    = 1;
  CHECK(quic_h3settings_zerortt_compatible(&prior, &current) == 0);
}

void test_h3settings_zerortt_compatible_wt_flow_control_lowered_rejected(void) {
  quic_h3settings_in prior = {
      .max_field_section_size      = 0x4000,
      .qpack_blocked_streams       = 100,
      .wt_initial_max_streams_uni  = 8,
      .wt_initial_max_streams_bidi = 8,
      .wt_initial_max_data         = 1 << 20};
  quic_h3settings_in bidi_lowered          = prior;
  bidi_lowered.wt_initial_max_streams_bidi = 1;
  CHECK(quic_h3settings_zerortt_compatible(&prior, &bidi_lowered) == 0);

  quic_h3settings_in data_lowered  = prior;
  data_lowered.wt_initial_max_data = 1;
  CHECK(quic_h3settings_zerortt_compatible(&prior, &data_lowered) == 0);
}
