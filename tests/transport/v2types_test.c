#include "test.h"

/* RFC 9369 3.2 wire values: Initial=1, 0-RTT=2, Handshake=3, Retry=0. */
static void test_v2_wire_values(void) {
  CHECK(v2_packet_type(LT_INITIAL) == 1);
  CHECK(v2_packet_type(LT_0RTT) == 2);
  CHECK(v2_packet_type(LT_HANDSHAKE) == 3);
  CHECK(v2_packet_type(LT_RETRY) == 0);
}

/* v1 wire values equal the logical ordering (RFC 9000 17.2). */
static void test_v1_wire_values(void) {
  CHECK(v1_packet_type(LT_INITIAL) == 0);
  CHECK(v1_packet_type(LT_0RTT) == 1);
  CHECK(v1_packet_type(LT_HANDSHAKE) == 2);
  CHECK(v1_packet_type(LT_RETRY) == 3);
}

/* logical -> wire -> logical round-trips for both versions, all 4 types. */
static void test_roundtrip(void) {
  for (int lt = 0; lt < 4; lt++) {
    CHECK(v1_logical_type(v1_packet_type(lt)) == lt);
    CHECK(v2_logical_type(v2_packet_type(lt)) == lt);
  }
}

/* Out-of-range logical types and wire values are rejected. */
static void test_invalid(void) {
  CHECK(v2_packet_type(LT_INVALID) == -1);
  CHECK(v1_packet_type((logical_type)4) == -1);
  CHECK(v2_logical_type(4) == LT_INVALID);
  CHECK(v1_logical_type(-1) == LT_INVALID);
}

void test_v2types(void) {
  test_v2_wire_values();
  test_v1_wire_values();
  test_roundtrip();
  test_invalid();
}
