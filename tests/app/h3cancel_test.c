#include "test.h"

static void test_h3cancel_error_code_value(void) {
  CHECK(H3_REQUEST_CANCELLED == 0x010c);
}

void test_h3cancel(void) { test_h3cancel_error_code_value(); }
