#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"

#include "app/http3/core/capsule/capsule.h"
#include "app/webtransport/session/session/session.h"
#include "test.h"

/* @file
 * WebTransport-specific capsule types (WT_CLOSE_SESSION 0x2843,
 * WT_DRAIN_SESSION 0x78ae) layered on the generic RFC 9297 Capsule Protocol
 * codec.
 */

/* TEST 1: WT_CLOSE_SESSION round-trip with a nonzero error code and a short
 * message. */
static void test_wtcapsule_close_roundtrip(void) {
  u8         buf[64];
  wired_obuf out    = obuf_of(buf, sizeof buf);
  u8         msg[5] = {'h', 'e', 'l', 'l', 'o'};
  usz        at     = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wired_wtcapsule_encode_close(
      &out, 0xDEADBEEF, wired_span_of(msg, sizeof msg)));
  CHECK(wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 0xDEADBEEF);
  CHECK(msg_out.n == 5);
  for (usz i = 0; i < 5; i++) CHECK(msg_out.p[i] == msg[i]);
  CHECK(at == out.len);
}

/* TEST 2: WT_CLOSE_SESSION with an empty message round-trips correctly. */
static void test_wtcapsule_close_roundtrip_empty_message(void) {
  u8         buf[32];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wired_wtcapsule_encode_close(&out, 1, wired_span_of(0, 0)));
  CHECK(wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 1);
  CHECK(msg_out.n == 0);
  CHECK(at == out.len);
}

/* TEST 3: encode rejects a message over 1024 bytes even with plenty of room
 * in out. */
static void test_wtcapsule_close_encode_rejects_long_message(void) {
  u8         buf[4096];
  wired_obuf out = obuf_of(buf, sizeof buf);
  u8         msg[WTCAPSULE_CLOSE_MESSAGE_MAX + 1];
  for (usz i = 0; i < sizeof msg; i++) msg[i] = 'x';

  CHECK(!wired_wtcapsule_encode_close(&out, 0, wired_span_of(msg, sizeof msg)));
  CHECK(out.len == 0);
}

/* TEST 4: WT_DRAIN_SESSION round-trip: *at advances by the full empty-body
 * capsule size. */
static void test_wtcapsule_drain_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;

  CHECK(wtcapsule_encode_drain(&out));
  /* 0x78ae > 0x3FFF -> 4-byte type varint + 1-byte length(0) = 5 */
  CHECK(out.len == 5);
  CHECK(wtcapsule_decode_drain(wired_span_of(buf, out.len), &at));
  CHECK(at == 5);
}

/* TEST 5: wrong-type-no-advance -- decode_close on a WT_DRAIN_SESSION
 * capsule must fail AND leave *at unchanged, so the caller can retry with
 * decode_drain from the same offset. */
static void test_wtcapsule_wrong_type_does_not_advance(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wtcapsule_encode_drain(&out));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
  /* Same position now succeeds as a drain decode. */
  CHECK(wtcapsule_decode_drain(wired_span_of(buf, out.len), &at));
  CHECK(at == out.len);
}

/* TEST 6: malformed WT_CLOSE_SESSION -- correctly typed 0x2843 but body too
 * short to hold the 32-bit error code. */
static void test_wtcapsule_close_decode_body_too_short(void) {
  u8         buf[16];
  wired_obuf out           = obuf_of(buf, sizeof buf);
  u8         short_body[2] = {0, 0};
  usz        at            = 0;
  u32        code_out;
  wired_span msg_out;

  /* Hand-encode a generic capsule with type 0x2843 but a 2-byte body
   * (shorter than the mandatory 4-byte error code). */
  CHECK(capsule_encode(
      &out, 0x2843, wired_span_of(short_body, sizeof short_body)));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
}

/* TEST 6b: encode accepts a message of exactly WTCAPSULE_CLOSE_MESSAGE_MAX
 * bytes (the boundary -- one below TEST 3's rejected MAX+1) and it
 * round-trips through decode unchanged. Draft-mandated 1024-byte cap
 * (V-0492/CVE-2026-21434, V-0497/L-0039). */
static void test_wtcapsule_close_message_max_len(void) {
  u8         buf[WTCAPSULE_CLOSE_MESSAGE_MAX + 64];
  wired_obuf out = obuf_of(buf, sizeof buf);
  u8         msg[WTCAPSULE_CLOSE_MESSAGE_MAX];
  for (usz i = 0; i < sizeof msg; i++) msg[i] = (u8)i;
  usz        at = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(wired_wtcapsule_encode_close(&out, 7, wired_span_of(msg, sizeof msg)));
  CHECK(wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 7);
  CHECK(msg_out.n == WTCAPSULE_CLOSE_MESSAGE_MAX);
  CHECK(at == out.len);
}

/* TEST 6c: decode rejects a WT_CLOSE_SESSION whose message portion exceeds
 * WTCAPSULE_CLOSE_MESSAGE_MAX, even though wired_wtcapsule_encode_close
 * itself can never produce one -- hand-build the oversized capsule via the
 * generic capsule_encode (as an on-wire attacker could) to prove the
 * decode-side check (wtcapsule_is_close) is independent of the encoder's
 * own guard. */
static void test_wtcapsule_decode_close_rejects_oversized(void) {
  u8         buf[WTCAPSULE_CLOSE_MESSAGE_MAX + 64];
  wired_obuf out = obuf_of(buf, sizeof buf);
  /* 4 = the mandatory 32-bit Application Error Code prefix, not visible
   * to this test as a macro (WTCAPSULE_CLOSE_CODE_LEN is file-local to
   * wtcapsule.c). */
  u8 body[4 + WTCAPSULE_CLOSE_MESSAGE_MAX + 1];
  for (usz i = 0; i < sizeof body; i++) body[i] = 0;
  usz        at = 0;
  u32        code_out;
  wired_span msg_out;

  CHECK(capsule_encode(&out, 0x2843, wired_span_of(body, sizeof body)));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
}

/* TEST 7: sequential decode -- WT_DRAIN_SESSION then WT_CLOSE_SESSION
 * back-to-back in one buffer. */
static void test_wtcapsule_sequential_drain_then_close(void) {
  u8         buf[64];
  wired_obuf out    = obuf_of(buf, sizeof buf);
  u8         msg[3] = {'h', 'i', '!'};
  usz        at     = 0;
  u32        code_out;
  wired_span msg_out;
  wired_span data;

  CHECK(wtcapsule_encode_drain(&out));
  CHECK(wired_wtcapsule_encode_close(&out, 42, wired_span_of(msg, sizeof msg)));
  data = wired_span_of(buf, out.len);

  CHECK(wtcapsule_decode_drain(data, &at));
  CHECK(wired_wtcapsule_decode_close(data, &at, &code_out, &msg_out));
  CHECK(code_out == 42);
  CHECK(msg_out.n == 3);
  CHECK(msg_out.p[2] == '!');
  CHECK(at == out.len);
}

/* TEST 8: the HTTP/3 WebTransport mapping defines no per-stream
 * flow-control capsule (a hypothetical WT_MAX_STREAM_DATA /
 * WT_STREAM_DATA_BLOCKED, as opposed to the per-SESSION WT_MAX_DATA family
 * at 0x190B4D3D etc., which wtcapsule.h does implement -- see
 * wtcapsule_decode_max_data). There is no wire codepoint to construct
 * for a per-stream type this SDK will never emit or receive, so this test
 * instead pins: decode_close/decode_drain reject ANY capsule type outside
 * their own two types without advancing *at, shown here using the
 * per-SESSION WT_MAX_DATA codepoint (0x190B4D3D) as a stand-in "some other
 * capsule type" probe. */
static void test_wtcapsule_no_per_stream_flow_control_capsule(void) {
  u8         buf[32];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u32        code_out;
  wired_span msg_out;
  u8         value[4] = {1, 2, 3, 4};

  /* 0x190B4D3D is WT_MAX_DATA, owned by decode_max_data, not decode_close
   * or decode_drain -- used here only as "a type those two don't own"
   * probe. */
  CHECK(
      capsule_encode(&out, 0x190B4D3DULL, wired_span_of(value, sizeof value)));
  CHECK(!wired_wtcapsule_decode_close(
      wired_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
  CHECK(!wtcapsule_decode_drain(wired_span_of(buf, out.len), &at));
  CHECK(at == 0);
}

/* TEST 9: WT_MAX_STREAMS bidi round-trip; the bidi type (0x190B4D3F) does
 * not decode as the uni variant. */
static void test_wtcapsule_max_streams_bidi_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_max_streams(&out, 1, 42));
  CHECK(!wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 0, &n_out));
  CHECK(at == 0);
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(n_out == 42);
  CHECK(at == out.len);
}

/* TEST 10: WT_MAX_STREAMS uni round-trip (distinct type 0x190B4D40). */
static void test_wtcapsule_max_streams_uni_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_max_streams(&out, 0, 7));
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 0, &n_out));
  CHECK(n_out == 7);
  CHECK(at == out.len);
}

/* TEST 11: WT_STREAMS_BLOCKED bidi/uni round-trip, same direction-typed
 * shape as WT_MAX_STREAMS. */
static void test_wtcapsule_streams_blocked_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_streams_blocked(&out, 1, 3));
  CHECK(wtcapsule_decode_streams_blocked(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(n_out == 3);
  CHECK(at == out.len);

  out.len = 0;
  at      = 0;
  CHECK(wtcapsule_encode_streams_blocked(&out, 0, 9));
  CHECK(wtcapsule_decode_streams_blocked(
      wired_span_of(buf, out.len), &at, 0, &n_out));
  CHECK(n_out == 9);
  CHECK(at == out.len);
}

/* TEST 12: WT_MAX_DATA round-trip (single type, 0x190B4D3D). */
static void test_wtcapsule_max_data_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_max_data(&out, 65536));
  CHECK(wtcapsule_decode_max_data(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(n_out == 65536);
  CHECK(at == out.len);
}

/* TEST 13: WT_DATA_BLOCKED round-trip (single type, 0x190B4D41); also
 * confirms it does not cross-decode as WT_MAX_DATA. */
static void test_wtcapsule_data_blocked_roundtrip(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(wtcapsule_encode_data_blocked(&out, 1024));
  CHECK(!wtcapsule_decode_max_data(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(at == 0);
  CHECK(
      wtcapsule_decode_data_blocked(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(n_out == 1024);
  CHECK(at == out.len);
}

/* TEST 14: malformed flow-control capsule -- correctly typed WT_MAX_DATA
 * but an empty body (no varint to read) is rejected without advancing. */
static void test_wtcapsule_max_data_decode_empty_body_rejected(void) {
  u8         buf[16];
  wired_obuf out = obuf_of(buf, sizeof buf);
  usz        at  = 0;
  u64        n_out;

  CHECK(capsule_encode(&out, 0x190B4D3DULL, wired_span_of(0, 0)));
  CHECK(!wtcapsule_decode_max_data(wired_span_of(buf, out.len), &at, &n_out));
  CHECK(at == 0);
}

/* TEST 15: malformed flow-control capsule -- correctly typed WT_MAX_STREAMS
 * (bidi) but trailing bytes after the varint are rejected without
 * advancing. */
static void test_wtcapsule_max_streams_decode_trailing_bytes_rejected(void) {
  u8         buf[16];
  wired_obuf out     = obuf_of(buf, sizeof buf);
  u8         body[2] = {5, 0xAA};
  usz        at      = 0;
  u64        n_out;

  CHECK(capsule_encode(&out, 0x190B4D3FULL, wired_span_of(body, sizeof body)));
  CHECK(!wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(at == 0);
}

/* TEST 16: draft-ietf-webtrans-http3-15 SS5.1 (WTH3-053): "If flow control
 * is not enabled, an endpoint shall ignore receipt of any flow control
 * capsules." No caller in src/ currently decodes a WT_MAX_STREAMS/
 * WT_MAX_DATA capsule off the wire (see WTH3-058/060/062's own gap notes),
 * so there is no live receive path yet where "ignore" is a decision an
 * endpoint makes -- decode success or failure is orthogonal to whether the
 * decoded value gets applied. What IS live is wired_wt_session's own
 * flow-control state (session.h SS5.3/5.4): a session that has never had
 * wired_wt_session_set_max_streams/set_max_data applied to it behaves
 * exactly as WTH3-053 prescribes for "flow control not enabled" --
 * opening streams and sending data stay unconditionally allowed. This
 * pins that a decoded-but-not-yet-applied capsule value (the shape any
 * future receive-path wiring would produce before calling
 * wired_wt_session_set_max_streams) has zero effect on the session until
 * a caller chooses to apply it -- i.e. "decode, then don't apply" IS the
 * ignore rule once the future receive path exists. */
static void test_wtcapsule_max_streams_decoded_value_ignored_until_applied(
    void) {
  u8               buf[16];
  wired_obuf       out = obuf_of(buf, sizeof buf);
  usz              at  = 0;
  u64              n_out;
  wired_wt_session s;

  wired_wt_session_init(&s, 4);
  CHECK(wtcapsule_encode_max_streams(&out, 1, 5));
  CHECK(wtcapsule_decode_max_streams(
      wired_span_of(buf, out.len), &at, 1, &n_out));
  CHECK(n_out == 5);
  /* Decoded successfully, but never applied to s (the "ignore" choice) --
   * the session's flow control stays unenabled, so it keeps allowing. */
  CHECK(wired_wt_session_stream_open_allowed(&s, 1) == 1);
  CHECK(wired_wt_session_stream_open_allowed(&s, 0) == 1);
}

/* TEST 17: wtcapsule_value_varint is the shared "body is exactly one varint"
 * well-formedness check (SS5.6: every session flow-control capsule's body):
 * accepts a sole varint, rejects trailing bytes and an empty body. */
static void test_wtcapsule_value_varint_sole_only(void) {
  u8  one[]   = {0x07};
  u8  trail[] = {0x07, 0x01};
  u64 v       = 0;
  CHECK(wtcapsule_value_varint(wired_span_of(one, sizeof one), &v) == 1);
  CHECK(v == 7);
  CHECK(wtcapsule_value_varint(wired_span_of(trail, sizeof trail), &v) == 0);
  CHECK(wtcapsule_value_varint(wired_span_of(one, 0), &v) == 0);
}

/* draft-ietf-webtrans-http3-16 SS6: the WT_CLOSE_SESSION Application Error
 * Message must be valid UTF-8 (RFC 3629). An empty message is vacuously
 * valid. */
static void test_wt_utf8_valid_empty(void) {
  CHECK(wtcapsule_utf8_valid(wired_span_of(0, 0)) == 1);
}

static void test_wt_utf8_valid_ascii(void) {
  static const u8 s[] = "hello, world";
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s - 1)) == 1);
}

/* U+00E9 (e acute) as its canonical 2-byte encoding. */
static void test_wt_utf8_valid_two_byte(void) {
  static const u8 s[] = {0xC3, 0xA9};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 1);
}

/* U+3042 (hiragana A) as its canonical 3-byte encoding. */
static void test_wt_utf8_valid_three_byte(void) {
  static const u8 s[] = {0xE3, 0x81, 0x82};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 1);
}

/* U+1F600 (grinning face) as its canonical 4-byte encoding. */
static void test_wt_utf8_valid_four_byte(void) {
  static const u8 s[] = {0xF0, 0x9F, 0x98, 0x80};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 1);
}

/* A lead byte announcing a 2-byte sequence with no continuation byte
 * following (truncated at the end of the message). */
static void test_wt_utf8_invalid_truncated_sequence(void) {
  static const u8 s[] = {0xC3};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 0);
}

/* A continuation byte (0x80-0xBF) with no lead byte before it. */
static void test_wt_utf8_invalid_stray_continuation(void) {
  static const u8 s[] = {0x80};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 0);
}

/* Overlong encoding: 0xC0 0x80 encodes NUL (U+0000) in 2 bytes instead of
 * the canonical 1 -- RFC 3629 SS3 forbids this. */
static void test_wt_utf8_invalid_overlong(void) {
  static const u8 s[] = {0xC0, 0x80};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 0);
}

/* A lead byte of 0xF5 would start a sequence encoding past U+10FFFF
 * (outside Unicode's range) -- RFC 3629 SS3. */
static void test_wt_utf8_invalid_lead_byte_out_of_range(void) {
  static const u8 s[] = {0xF5, 0x80, 0x80, 0x80};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 0);
}

/* 0xED 0xA0 0x80 encodes U+D800, a UTF-16 surrogate half -- never a valid
 * UTF-8 scalar value (RFC 3629 SS3). */
static void test_wt_utf8_invalid_surrogate(void) {
  static const u8 s[] = {0xED, 0xA0, 0x80};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 0);
}

/* 0xFF is never a valid UTF-8 lead byte. */
static void test_wt_utf8_invalid_lead_byte(void) {
  static const u8 s[] = {0xFF};
  CHECK(wtcapsule_utf8_valid(wired_span_of(s, sizeof s)) == 0);
}

/* draft-ietf-webtrans-http3-16 SS6: truncating to a cap at or past the
 * message's own length is a no-op. */
static void test_wt_utf8_truncate_len_no_truncation_needed(void) {
  static const u8 s[] = "hello";
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(s, 5), 5) == 5);
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(s, 5), 100) == 5);
}

/* Pure ASCII: every byte is its own boundary, so the cap itself is exact. */
static void test_wt_utf8_truncate_len_ascii_exact_cap(void) {
  static const u8 s[] = "hello, world";
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(s, sizeof s - 1), 5) == 5);
}

/* "e" + U+00E9 (0xC3 0xA9) straddling byte 2: a cap of 2 lands inside the
 * 2-byte sequence, so the boundary backs off to 1 (before the sequence
 * starts), never 2 (which would split it). */
static void test_wt_utf8_truncate_len_backs_off_before_split_sequence(void) {
  static const u8 s[] = {'e', 0xC3, 0xA9};
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(s, sizeof s), 2) == 1);
}

/* Same string, cap of 3: the 2-byte sequence ends exactly at the cap, so
 * the full cap is kept (no truncation within the sequence). */
static void test_wt_utf8_truncate_len_keeps_sequence_ending_at_cap(void) {
  static const u8 s[] = {'e', 0xC3, 0xA9};
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(s, sizeof s), 3) == 3);
}

/* An invalid lead byte (0x80 / 0xFF) before the cap ends the prefix there
 * instead of looping forever (seq_len 0 never advances the scan). */
static void test_wt_utf8_truncate_len_stops_at_invalid_byte_before_cap(void) {
  static const u8 a[] = {'a', 'b', 0x80, 'c', 'd', 'e'};
  static const u8 b[] = {'a', 0xFF, 'c', 'd', 'e', 'f'};
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(a, sizeof a), 4) == 2);
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(b, sizeof b), 4) == 1);
}

/* An invalid byte past the cap is never reached: the prefix up to the cap is
 * kept whole. */
static void test_wt_utf8_truncate_len_ignores_invalid_byte_after_cap(void) {
  static const u8 s[] = {'a', 'b', 'c', 'd', 0xFF, 0x80};
  CHECK(wtcapsule_utf8_truncate_len(wired_span_of(s, sizeof s), 4) == 4);
}

void test_wtcapsule(void) {
  test_wtcapsule_close_roundtrip();
  test_wtcapsule_close_roundtrip_empty_message();
  test_wtcapsule_close_encode_rejects_long_message();
  test_wtcapsule_close_message_max_len();
  test_wtcapsule_decode_close_rejects_oversized();
  test_wtcapsule_drain_roundtrip();
  test_wtcapsule_wrong_type_does_not_advance();
  test_wtcapsule_close_decode_body_too_short();
  test_wtcapsule_sequential_drain_then_close();
  test_wtcapsule_no_per_stream_flow_control_capsule();
  test_wtcapsule_max_streams_bidi_roundtrip();
  test_wtcapsule_max_streams_uni_roundtrip();
  test_wtcapsule_streams_blocked_roundtrip();
  test_wtcapsule_max_data_roundtrip();
  test_wtcapsule_data_blocked_roundtrip();
  test_wtcapsule_max_data_decode_empty_body_rejected();
  test_wtcapsule_max_streams_decode_trailing_bytes_rejected();
  test_wtcapsule_max_streams_decoded_value_ignored_until_applied();
  test_wtcapsule_value_varint_sole_only();
  test_wt_utf8_valid_empty();
  test_wt_utf8_valid_ascii();
  test_wt_utf8_valid_two_byte();
  test_wt_utf8_valid_three_byte();
  test_wt_utf8_valid_four_byte();
  test_wt_utf8_invalid_truncated_sequence();
  test_wt_utf8_invalid_stray_continuation();
  test_wt_utf8_invalid_overlong();
  test_wt_utf8_invalid_lead_byte_out_of_range();
  test_wt_utf8_invalid_surrogate();
  test_wt_utf8_invalid_lead_byte();
  test_wt_utf8_truncate_len_no_truncation_needed();
  test_wt_utf8_truncate_len_ascii_exact_cap();
  test_wt_utf8_truncate_len_backs_off_before_split_sequence();
  test_wt_utf8_truncate_len_keeps_sequence_ending_at_cap();
  test_wt_utf8_truncate_len_stops_at_invalid_byte_before_cap();
  test_wt_utf8_truncate_len_ignores_invalid_byte_after_cap();
}
