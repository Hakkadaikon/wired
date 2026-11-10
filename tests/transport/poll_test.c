#include "test.h"

/* pollfd is built for read-readiness: fd set, events=POLLIN, revents cleared.
 */
static void test_fill_readable(void) {
  pollfd p;
  p.revents = 0xFFFF; /* dirty; fill must clear it */
  poll_fill_readable(&p, 7);
  CHECK(p.fd == 7);
  CHECK(p.events == POLLIN);
  CHECK(p.events == 0x001);
  CHECK(p.revents == 0);
}

/* Kernel-facing pollfd layout: 4-byte fd then two shorts (8 bytes total). */
static void test_pollfd_layout(void) { CHECK(sizeof(pollfd) == 8); }

/* No real socket: F_SETFL on a bad fd must fail with a negative errno. */
static void test_set_nonblock_badfd(void) { CHECK(poll_set_nonblock(-1) < 0); }

void test_poll(void) {
  test_fill_readable();
  test_pollfd_layout();
  test_set_nonblock_badfd();
}
