#include "test.h"

static void test_shutdown_processes(void) {
  CHECK(h3_shutdown_processes(4, 8));   /* below limit: processed */
  CHECK(!h3_shutdown_processes(8, 8));  /* at limit: refused */
  CHECK(!h3_shutdown_processes(12, 8)); /* above limit: refused */
  CHECK(!h3_shutdown_processes(0, 0));  /* nothing below 0 */
}

static void test_shutdown_id_monotone(void) {
  CHECK(h3_shutdown_id_monotone(8, 4));  /* narrowing: valid */
  CHECK(h3_shutdown_id_monotone(8, 8));  /* repeat: valid */
  CHECK(!h3_shutdown_id_monotone(4, 8)); /* increase: invalid */
}

void test_shutdown(void) {
  test_shutdown_processes();
  test_shutdown_id_monotone();
}
