#include "app/http3/server/srvpoll/srvpoll.h"

/* ponytail: PAUSE has no observable side effect for tests to assert on; its
 * only job is "don't spin the CPU at full tilt while empty". */
i64 wired_srvpoll_spin_step(i64 fd, quic_mmsg_buf* bufs, usz count) {
  i64 r = wired_udp_recvmmsg_nowait(fd, bufs, count);
  if (r <= 0) __builtin_ia32_pause();
  return r;
}
