#include "test.h"

/* Each long-header type byte maps to its logical type under v1 (RFC 9000
 * 17.2). */
static void test_ptype_each(void) {
  CHECK(quic_packet_long_type(0xC0, QUIC_VERSION_1) == QUIC_PT_INITIAL);
  /* 0b00 */
  CHECK(quic_packet_long_type(0xD0, QUIC_VERSION_1) == QUIC_PT_0RTT);
  /* 0b01 */
  CHECK(quic_packet_long_type(0xE0, QUIC_VERSION_1) == QUIC_PT_HANDSHAKE);
  /* 0b10 */
  CHECK(quic_packet_long_type(0xF0, QUIC_VERSION_1) == QUIC_PT_RETRY);
  /* 0b11 */
}

/* A short-header byte has no long type, for any version. */
static void test_ptype_short(void) {
  CHECK(quic_packet_is_long(0x40) == 0);
  CHECK(quic_packet_long_type(0x40, QUIC_VERSION_1) == QUIC_PT_NONE);
  CHECK(quic_packet_long_type(0x40, QUIC_VERSION_2) == QUIC_PT_NONE);
  CHECK(quic_packet_is_long(0xC0) == 1);
}

/* The reserved/fixed low bits do not affect the decoded type. */
static void test_ptype_lowbits(void) {
  CHECK(quic_packet_long_type(0xCF, QUIC_VERSION_1) == QUIC_PT_INITIAL);
  /* low bits set */
  CHECK(quic_packet_long_type(0xFF, QUIC_VERSION_1) == QUIC_PT_RETRY);
}

/* RFC 9369 3.2: v2 rotates the wire values (Initial=1, 0-RTT=2,
 * Handshake=3, Retry=0), so the same wire bits decode differently than v1. */
static void test_ptype_v2(void) {
  CHECK(quic_packet_long_type(0xD0, QUIC_VERSION_2) == QUIC_PT_INITIAL);
  /* wire 0b01 */
  CHECK(quic_packet_long_type(0xE0, QUIC_VERSION_2) == QUIC_PT_0RTT);
  /* wire 0b10 */
  CHECK(quic_packet_long_type(0xF0, QUIC_VERSION_2) == QUIC_PT_HANDSHAKE);
  /* wire 0b11 */
  CHECK(quic_packet_long_type(0xC0, QUIC_VERSION_2) == QUIC_PT_RETRY);
  /* wire 0b00 */
}

/* A version this SDK does not know the type-bit layout for decodes as
 * QUIC_PT_NONE rather than silently falling back to v1's layout. */
static void test_ptype_unknown_version(void) {
  CHECK(quic_packet_long_type(0xC0, 0xdeadbeefu) == QUIC_PT_NONE);
}

void test_ptype(void) {
  test_ptype_each();
  test_ptype_short();
  test_ptype_lowbits();
  test_ptype_v2();
  test_ptype_unknown_version();
}
