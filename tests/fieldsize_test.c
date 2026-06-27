#include "test.h"

static void test_field_section_ok(void)
{
    CHECK(quic_h3_field_section_ok(100, 0));    /* max 0 = unlimited */
    CHECK(quic_h3_field_section_ok(0, 0));
    CHECK(quic_h3_field_section_ok(99, 100));   /* below limit */
    CHECK(quic_h3_field_section_ok(100, 100));  /* at limit: ok */
    CHECK(!quic_h3_field_section_ok(101, 100)); /* over limit: error */
}

void test_fieldsize(void)
{
    test_field_section_ok();
}
