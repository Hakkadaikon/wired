#include "test.h"
#include "version/v2types.c"

/* RFC 9369 3.2 wire values: Initial=1, 0-RTT=2, Handshake=3, Retry=0. */
static void test_v2_wire_values(void)
{
    CHECK(quic_v2_packet_type(QUIC_LT_INITIAL)   == 1);
    CHECK(quic_v2_packet_type(QUIC_LT_0RTT)      == 2);
    CHECK(quic_v2_packet_type(QUIC_LT_HANDSHAKE) == 3);
    CHECK(quic_v2_packet_type(QUIC_LT_RETRY)     == 0);
}

/* v1 wire values equal the logical ordering (RFC 9000 17.2). */
static void test_v1_wire_values(void)
{
    CHECK(quic_v1_packet_type(QUIC_LT_INITIAL)   == 0);
    CHECK(quic_v1_packet_type(QUIC_LT_0RTT)      == 1);
    CHECK(quic_v1_packet_type(QUIC_LT_HANDSHAKE) == 2);
    CHECK(quic_v1_packet_type(QUIC_LT_RETRY)     == 3);
}

/* logical -> wire -> logical round-trips for both versions, all 4 types. */
static void test_roundtrip(void)
{
    for (int lt = 0; lt < 4; lt++) {
        CHECK(quic_v1_logical_type(quic_v1_packet_type(lt)) == lt);
        CHECK(quic_v2_logical_type(quic_v2_packet_type(lt)) == lt);
    }
}

/* Out-of-range logical types and wire values are rejected. */
static void test_invalid(void)
{
    CHECK(quic_v2_packet_type(QUIC_LT_INVALID) == -1);
    CHECK(quic_v1_packet_type((quic_logical_type)4) == -1);
    CHECK(quic_v2_logical_type(4) == QUIC_LT_INVALID);
    CHECK(quic_v1_logical_type(-1) == QUIC_LT_INVALID);
}

void test_v2types(void)
{
    test_v2_wire_values();
    test_v1_wire_values();
    test_roundtrip();
    test_invalid();
}
