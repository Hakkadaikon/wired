#include "test.h"

static void test_field_section_ok(void) {
  CHECK(h3_field_section_ok(100, 0)); /* max 0 = unlimited */
  CHECK(h3_field_section_ok(0, 0));
  CHECK(h3_field_section_ok(99, 100));   /* below limit */
  CHECK(h3_field_section_ok(100, 100));  /* at limit: ok */
  CHECK(!h3_field_section_ok(101, 100)); /* over limit: error */
}

void test_fieldsize(void) { test_field_section_ok(); }
