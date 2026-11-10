#include "test.h"

/* RFC 9002 6.2.4: a fired PTO sends 2 probe packets. */
static void test_probe_count(void) {
  CHECK(probe_count(1) == 2);
  CHECK(probe_count(0) == 0);
}

void test_probe(void) { test_probe_count(); }
