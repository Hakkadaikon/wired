#include "app/http3/core/capsule/capsule.h"

#include "test.h"

/* @file
 * tasks/webtransport-plan.md Phase 2 coder A -- RFC 9297 SS3.2 Capsule
 * Protocol codec tests. Generic type+length+value envelope round-trip;
 * no WebTransport-specific capsule types (that is a later domain).
 */

/* TEST 1: round-trip a small type (RFC 9297 base DATAGRAM capsule type 0x00)
 * with a short value. */
static void test_capsule_roundtrip_small_type(void) {
  u8        buf[32];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  u8        val[5]  = {1, 2, 3, 4, 5};
  quic_span value_in = quic_span_of(val, sizeof val);
  usz       at = 0;
  u64       type_out;
  quic_span value_out;

  CHECK(quic_capsule_encode(&out, 0x00, value_in));
  /* type varint(1B) + length varint(1B) + 5 value bytes = 7 */
  CHECK(out.len == 7);

  CHECK(quic_capsule_decode(quic_span_of(buf, out.len), &at, &type_out, &value_out));
  CHECK(type_out == 0x00);
  CHECK(value_out.n == 5);
  for (usz i = 0; i < 5; i++) CHECK(value_out.p[i] == val[i]);
  CHECK(at == 7);
}

/* TEST 2: round-trip with large types requiring multi-byte varints
 * (0x2843 -> 2-byte varint, 0x190B4D3D -> 4-byte varint per RFC 9000 SS16). */
static void test_capsule_roundtrip_large_types(void) {
  u8        buf[32];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  u8        val[3]  = {0xAA, 0xBB, 0xCC};
  quic_span value_in = quic_span_of(val, sizeof val);
  usz       at = 0;
  u64       type_out;
  quic_span value_out;

  CHECK(quic_capsule_encode(&out, 0x2843, value_in));
  CHECK(quic_capsule_decode(quic_span_of(buf, out.len), &at, &type_out, &value_out));
  CHECK(type_out == 0x2843);
  CHECK(value_out.n == 3);
  CHECK(at == out.len);

  {
    u8        buf2[32];
    quic_obuf out2 = quic_obuf_of(buf2, sizeof buf2);
    usz       at2  = 0;
    u64       type_out2;
    quic_span value_out2;

    CHECK(quic_capsule_encode(&out2, 0x190B4D3DULL, value_in));
    CHECK(quic_capsule_decode(quic_span_of(buf2, out2.len), &at2, &type_out2, &value_out2));
    CHECK(type_out2 == 0x190B4D3DULL);
    CHECK(value_out2.n == 3);
  }
}

/* TEST 3: empty value (Length=0) round-trips correctly. */
static void test_capsule_roundtrip_empty_value(void) {
  u8        buf[16];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  quic_span value_in = quic_span_of(0, 0);
  usz       at = 0;
  u64       type_out;
  quic_span value_out;

  CHECK(quic_capsule_encode(&out, 0x78ae, value_in));
  CHECK(out.len == 5); /* 0x78ae > 0x3FFF -> 4-byte type varint + 1-byte length(0) */
  CHECK(quic_capsule_decode(quic_span_of(buf, out.len), &at, &type_out, &value_out));
  CHECK(type_out == 0x78ae);
  CHECK(value_out.n == 0);
  CHECK(at == out.len);
}

/* TEST 4: decode with insufficient bytes for even the type varint. */
static void test_capsule_decode_truncated_type(void) {
  u8        buf[1] = {0xC0}; /* prefix bits say 8-byte varint, only 1 present */
  usz       at = 0;
  u64       type_out;
  quic_span value_out;

  CHECK(!quic_capsule_decode(quic_span_of(buf, 1), &at, &type_out, &value_out));
  CHECK(at == 0);
}

/* TEST 5: complete type+length header but insufficient value bytes. */
static void test_capsule_decode_truncated_value(void) {
  u8        buf[16];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  u8        val[5] = {1, 2, 3, 4, 5};
  usz       at = 0;
  u64       type_out;
  quic_span value_out;

  CHECK(quic_capsule_encode(&out, 0x01, quic_span_of(val, sizeof val)));
  /* Truncate: hand decode only the header plus 2 of the 5 value bytes. */
  CHECK(!quic_capsule_decode(quic_span_of(buf, out.len - 3), &at, &type_out, &value_out));
  CHECK(at == 0);
}

/* TEST 6: encode into a buffer too small to hold the result fails, and
 * leaves out unmodified (contract: no partial write on failure). */
static void test_capsule_encode_too_small_leaves_out_unmodified(void) {
  u8        buf[3] = {0xEE, 0xEE, 0xEE};
  quic_obuf out    = quic_obuf_of(buf, sizeof buf);
  u8        val[5] = {1, 2, 3, 4, 5};

  CHECK(!quic_capsule_encode(&out, 0x00, quic_span_of(val, sizeof val)));
  CHECK(out.len == 0);
  CHECK(buf[0] == 0xEE);
  CHECK(buf[1] == 0xEE);
  CHECK(buf[2] == 0xEE);
}

/* TEST 7: multiple capsules back-to-back in one buffer. */
static void test_capsule_decode_multiple_back_to_back(void) {
  u8        buf[64];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  u8        val1[2] = {0x11, 0x22};
  u8        val2[3] = {0x33, 0x44, 0x55};
  usz       at = 0;
  u64       type_out;
  quic_span value_out;
  quic_span data;

  CHECK(quic_capsule_encode(&out, 0x00, quic_span_of(val1, sizeof val1)));
  CHECK(quic_capsule_encode(&out, 0x2843, quic_span_of(val2, sizeof val2)));
  data = quic_span_of(buf, out.len);

  CHECK(quic_capsule_decode(data, &at, &type_out, &value_out));
  CHECK(type_out == 0x00);
  CHECK(value_out.n == 2);
  CHECK(value_out.p[0] == 0x11);

  CHECK(quic_capsule_decode(data, &at, &type_out, &value_out));
  CHECK(type_out == 0x2843);
  CHECK(value_out.n == 3);
  CHECK(value_out.p[2] == 0x55);
  CHECK(at == out.len);
}

/* TEST 8: mutation-style check -- two different capsules with the same value
 * bytes decode to different types (guards a copy-paste type hardcode bug). */
static void test_capsule_different_types_same_value_bytes(void) {
  u8        buf[64];
  quic_obuf out = quic_obuf_of(buf, sizeof buf);
  u8        val[4] = {9, 9, 9, 9};
  usz       at1 = 0, at2;
  u64       type1, type2;
  quic_span value1, value2;
  quic_span data;

  CHECK(quic_capsule_encode(&out, 0x05, quic_span_of(val, sizeof val)));
  at2 = out.len;
  CHECK(quic_capsule_encode(&out, 0x06, quic_span_of(val, sizeof val)));
  data = quic_span_of(buf, out.len);

  CHECK(quic_capsule_decode(data, &at1, &type1, &value1));
  CHECK(quic_capsule_decode(data, &at2, &type2, &value2));
  CHECK(type1 == 0x05);
  CHECK(type2 == 0x06);
  CHECK(type1 != type2);
}

void test_capsule(void) {
  test_capsule_roundtrip_small_type();
  test_capsule_roundtrip_large_types();
  test_capsule_roundtrip_empty_value();
  test_capsule_decode_truncated_type();
  test_capsule_decode_truncated_value();
  test_capsule_encode_too_small_leaves_out_unmodified();
  test_capsule_decode_multiple_back_to_back();
  test_capsule_different_types_same_value_bytes();
}
