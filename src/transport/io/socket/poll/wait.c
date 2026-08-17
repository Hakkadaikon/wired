#include "transport/io/socket/poll/wait.h"

void poll_fill_readable(pollfd* p, i64 fd) {
  p->fd      = (i32)fd;
  p->events  = QUIC_POLLIN;
  p->revents = 0;
}

static i64 poll_result(i64 r, u16 revents) {
  if (r < 0) return r;
  /* r == 0 means timeout: revents is 0, so POLLIN test yields 0. */
  return (revents & QUIC_POLLIN) ? 1 : 0;
}

i64 poll_wait_readable(i64 fd, u64 timeout_ms) {
  pollfd p;
  poll_fill_readable(&p, fd);
  i64 r = wired_arch_poll(&p, 1, (i32)timeout_ms);
  return poll_result(r, p.revents);
}
