#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"

#include "app/http3/core/capsule/capsule.h"
#include "test.h"

/* @file
 * tasks/webtransport-plan.md Phase 6 coder F -- WebTransport-specific
 * capsule types (WT_CLOSE_SESSION 0x2843, WT_DRAIN_SESSION 0x78ae) layered
 * on the generic RFC 9297 Capsule Protocol codec.
 */

/* TEST 1: WT_CLOSE_SESSION round-trip with a nonzero error code and a short
 * message. */
static void test_wtcapsule_close_roundtrip(void) {
  u8        buf[64];
  quic_obuf out    = quic_obuf_of(buf, sizeof buf);
  u8        msg[5] = {'h', 'e', 'l', 'l', 'o'};
  usz       at     = 0;
  u32       code_out;
  quic_span msg_out;

  CHECK(quic_wtcapsule_encode_close(
      &out, 0xDEADBEEF, quic_span_of(msg, sizeof msg)));
  CHECK(quic_wtcapsule_decode_close(
      quic_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 0xDEADBEEF);
  CHECK(msg_out.n == 5);
  for (usz i = 0; i < 5; i++) CHECK(msg_out.p[i] == msg[i]);
  CHECK(at == out.len);
}

/* TEST 2: WT_CLOSE_SESSION with an empty message round-trips correctly. */
static void test_wtcapsule_close_roundtrip_empty_message(void) {
  u8        buf[32];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  usz       at  = 0;
  u32       code_out;
  quic_span msg_out;

  CHECK(quic_wtcapsule_encode_close(&out, 1, quic_span_of(0, 0)));
  CHECK(quic_wtcapsule_decode_close(
      quic_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(code_out == 1);
  CHECK(msg_out.n == 0);
  CHECK(at == out.len);
}

/* TEST 3: encode rejects a message over 1024 bytes even with plenty of room
 * in out. */
static void test_wtcapsule_close_encode_rejects_long_message(void) {
  u8        buf[4096];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  u8        msg[QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX + 1];
  for (usz i = 0; i < sizeof msg; i++) msg[i] = 'x';

  CHECK(!quic_wtcapsule_encode_close(&out, 0, quic_span_of(msg, sizeof msg)));
  CHECK(out.len == 0);
}

/* TEST 4: WT_DRAIN_SESSION round-trip: *at advances by the full empty-body
 * capsule size. */
static void test_wtcapsule_drain_roundtrip(void) {
  u8        buf[16];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  usz       at  = 0;

  CHECK(quic_wtcapsule_encode_drain(&out));
  /* 0x78ae > 0x3FFF -> 4-byte type varint + 1-byte length(0) = 5 */
  CHECK(out.len == 5);
  CHECK(quic_wtcapsule_decode_drain(quic_span_of(buf, out.len), &at));
  CHECK(at == 5);
}

/* TEST 5: wrong-type-no-advance -- decode_close on a WT_DRAIN_SESSION
 * capsule must fail AND leave *at unchanged, so the caller can retry with
 * decode_drain from the same offset. */
static void test_wtcapsule_wrong_type_does_not_advance(void) {
  u8        buf[16];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  usz       at  = 0;
  u32       code_out;
  quic_span msg_out;

  CHECK(quic_wtcapsule_encode_drain(&out));
  CHECK(!quic_wtcapsule_decode_close(
      quic_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
  /* Same position now succeeds as a drain decode. */
  CHECK(quic_wtcapsule_decode_drain(quic_span_of(buf, out.len), &at));
  CHECK(at == out.len);
}

/* TEST 6: malformed WT_CLOSE_SESSION -- correctly typed 0x2843 but body too
 * short to hold the 32-bit error code. */
static void test_wtcapsule_close_decode_body_too_short(void) {
  u8        buf[16];
  quic_obuf out           = quic_obuf_of(buf, sizeof buf);
  u8        short_body[2] = {0, 0};
  usz       at            = 0;
  u32       code_out;
  quic_span msg_out;

  /* Hand-encode a generic capsule with type 0x2843 but a 2-byte body
   * (shorter than the mandatory 4-byte error code). */
  CHECK(quic_capsule_encode(
      &out, 0x2843, quic_span_of(short_body, sizeof short_body)));
  CHECK(!quic_wtcapsule_decode_close(
      quic_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
}

/* TEST 7: sequential decode -- WT_DRAIN_SESSION then WT_CLOSE_SESSION
 * back-to-back in one buffer. */
static void test_wtcapsule_sequential_drain_then_close(void) {
  u8        buf[64];
  quic_obuf out    = quic_obuf_of(buf, sizeof buf);
  u8        msg[3] = {'h', 'i', '!'};
  usz       at     = 0;
  u32       code_out;
  quic_span msg_out;
  quic_span data;

  CHECK(quic_wtcapsule_encode_drain(&out));
  CHECK(quic_wtcapsule_encode_close(&out, 42, quic_span_of(msg, sizeof msg)));
  data = quic_span_of(buf, out.len);

  CHECK(quic_wtcapsule_decode_drain(data, &at));
  CHECK(quic_wtcapsule_decode_close(data, &at, &code_out, &msg_out));
  CHECK(code_out == 42);
  CHECK(msg_out.n == 3);
  CHECK(msg_out.p[2] == '!');
  CHECK(at == out.len);
}

/* TEST 8: WT-E-010 pin -- the HTTP/3 WebTransport mapping defines no
 * per-stream flow-control capsule (a hypothetical WT_MAX_STREAM_DATA /
 * WT_STREAM_DATA_BLOCKED, as opposed to the legitimately-deferred
 * per-SESSION WT_MAX_DATA family at 0x190B4D3D etc. -- see
 * tasks/webtransport-plan.md WT-E-004..009 vs WT-E-010). There is no wire
 * codepoint to construct for a type this SDK will never emit or receive, so
 * this test instead pins the two facts that ARE checkable:
 *
 * 1. wtcapsule.h's decode functions reject ANY capsule type outside its own
 *    {WT_CLOSE_SESSION, WT_DRAIN_SESSION} set without advancing *at -- shown
 *    here using the per-SESSION WT_MAX_DATA codepoint (0x190B4D3D) as a
 *    stand-in "some other capsule type" probe, since no per-stream
 *    codepoint is defined anywhere to construct one from.
 * 2. wtcapsule.h declares exactly four functions (encode/decode close,
 *    encode/decode drain) -- confirmed by the grep in this task's report,
 *    not expressible as a runtime assertion in C.
 */
static void test_wtcapsule_no_per_stream_flow_control_capsule(void) {
  u8        buf[32];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  usz       at  = 0;
  u32       code_out;
  quic_span msg_out;
  u8        value[4] = {1, 2, 3, 4};

  /* 0x190B4D3D is WT_MAX_DATA (per-SESSION, deferred per WT-E-004..009) --
   * used only as "a capsule type wtcapsule does not own" probe. */
  CHECK(quic_capsule_encode(
      &out, 0x190B4D3DULL, quic_span_of(value, sizeof value)));
  CHECK(!quic_wtcapsule_decode_close(
      quic_span_of(buf, out.len), &at, &code_out, &msg_out));
  CHECK(at == 0);
  CHECK(!quic_wtcapsule_decode_drain(quic_span_of(buf, out.len), &at));
  CHECK(at == 0);
}

void test_wtcapsule(void) {
  test_wtcapsule_close_roundtrip();
  test_wtcapsule_close_roundtrip_empty_message();
  test_wtcapsule_close_encode_rejects_long_message();
  test_wtcapsule_drain_roundtrip();
  test_wtcapsule_wrong_type_does_not_advance();
  test_wtcapsule_close_decode_body_too_short();
  test_wtcapsule_sequential_drain_then_close();
  test_wtcapsule_no_per_stream_flow_control_capsule();
}
