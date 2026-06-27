#include "test.h"

/* All-lowercase field names are accepted. */
static void test_headercase_lower(void)
{
    CHECK(quic_h3_header_name_ok((const u8 *)"content-type", 12) == 1);
    CHECK(quic_h3_header_name_ok((const u8 *)":path", 5) == 1);
    CHECK(quic_h3_header_name_ok((const u8 *)"", 0) == 1);
}

/* Any uppercase letter makes the name malformed (H3_MESSAGE_ERROR). */
static void test_headercase_upper(void)
{
    CHECK(quic_h3_header_name_ok((const u8 *)"Content-Type", 12) == 0);
    CHECK(quic_h3_header_name_ok((const u8 *)"hostX", 5) == 0);
    CHECK(quic_h3_header_name_ok((const u8 *)"Authorization", 13) == 0);
}

/* Boundary bytes around A-Z stay allowed. */
static void test_headercase_boundary(void)
{
    CHECK(quic_h3_header_name_ok((const u8 *)"@[", 2) == 1);   /* 0x40, 0x5b */
    CHECK(quic_h3_header_name_ok((const u8 *)"a-z_0", 5) == 1);
}

void test_headercase(void)
{
    test_headercase_lower();
    test_headercase_upper();
    test_headercase_boundary();
}
