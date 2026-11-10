#include "test.h"

/* RFC 9218 4.1: defaults are urgency 3, non-incremental. */
static void test_priority_init_defaults(void) {
  h3_priority p;
  h3_priority_init(&p);
  CHECK(p.urgency == 3);
  CHECK(p.incremental == 0);
}

void test_priority(void) { test_priority_init_defaults(); }
