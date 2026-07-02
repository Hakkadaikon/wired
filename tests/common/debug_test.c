#include "common/platform/debug/debug.h"

#include "test.h"

/* wired_fmt_u64: decimal formatting with zero-padding to a minimum width. */
static void test_debug_fmt_u64(void) {
  char buf[32];
  usz  at;

  at = 0;
  wired_fmt_u64(buf, &at, 0, 1);
  CHECK(at == 1 && buf[0] == '0');

  at = 0;
  wired_fmt_u64(buf, &at, 12345, 1);
  CHECK(at == 5);
  CHECK(buf[0] == '1' && buf[4] == '5');

  /* width pads with leading zeros; the value is longer than width -> no pad. */
  at = 0;
  wired_fmt_u64(buf, &at, 42, 5);
  CHECK(at == 5);
  CHECK(
      buf[0] == '0' && buf[1] == '0' && buf[2] == '0' && buf[3] == '4' &&
      buf[4] == '2');

  /* appends at the running offset rather than the start. */
  at     = 2;
  buf[0] = 'x';
  buf[1] = 'y';
  wired_fmt_u64(buf, &at, 7, 1);
  CHECK(at == 3 && buf[0] == 'x' && buf[1] == 'y' && buf[2] == '7');
}

void test_debug(void) { test_debug_fmt_u64(); }
