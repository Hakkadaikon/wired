#include "test.h"

/* Each long-header type byte maps to its logical type (RFC 9000 17.2). */
static void test_ptype_each(void)
{
    CHECK(quic_packet_long_type(0xC0) == QUIC_PT_INITIAL);   /* 0b00 */
    CHECK(quic_packet_long_type(0xD0) == QUIC_PT_0RTT);      /* 0b01 */
    CHECK(quic_packet_long_type(0xE0) == QUIC_PT_HANDSHAKE); /* 0b10 */
    CHECK(quic_packet_long_type(0xF0) == QUIC_PT_RETRY);     /* 0b11 */
}

/* A short-header byte has no long type. */
static void test_ptype_short(void)
{
    CHECK(quic_packet_is_long(0x40) == 0);
    CHECK(quic_packet_long_type(0x40) == QUIC_PT_NONE);
    CHECK(quic_packet_is_long(0xC0) == 1);
}

/* The reserved/fixed low bits do not affect the decoded type. */
static void test_ptype_lowbits(void)
{
    CHECK(quic_packet_long_type(0xCF) == QUIC_PT_INITIAL); /* low bits set */
    CHECK(quic_packet_long_type(0xFF) == QUIC_PT_RETRY);
}

void test_ptype(void)
{
    test_ptype_each();
    test_ptype_short();
    test_ptype_lowbits();
}
