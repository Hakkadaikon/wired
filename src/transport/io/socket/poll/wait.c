#include "transport/io/socket/poll/wait.h"

#define SYS_poll 7 /* x86_64 poll(fds, nfds, timeout_ms) */

void quic_poll_fill_readable(quic_pollfd* p, i64 fd) {
  p->fd      = (i32)fd;
  p->events  = QUIC_POLLIN;
  p->revents = 0;
}

static i64 poll_result(i64 r, u16 revents) {
  if (r < 0) return r;
  /* r == 0 means timeout: revents is 0, so POLLIN test yields 0. */
  return (revents & QUIC_POLLIN) ? 1 : 0;
}

i64 quic_poll_wait_readable(i64 fd, u64 timeout_ms) {
  quic_pollfd p;
  quic_poll_fill_readable(&p, fd);
  i64 r = syscall3(SYS_poll, &p, 1, (i64)(i32)timeout_ms);
  return poll_result(r, p.revents);
}
