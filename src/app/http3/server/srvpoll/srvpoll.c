#include "app/http3/server/srvpoll/srvpoll.h"

/* ponytail: PAUSE has no observable side effect for tests to assert on; its
 * only job is "don't spin the CPU at full tilt while empty". */
i64 wired_srvpoll_spin_step(i64 fd, quic_mmsg_buf* bufs, usz count) {
  i64 r = wired_udp_recvmmsg_nowait(fd, bufs, count);
  if (r <= 0) __builtin_ia32_pause();
  return r;
}

/* ponytail: spin-count-based backoff, not time-based -- this repo's only
 * clock (quic_clock_mono_ms) is millisecond-granular, far coarser than one
 * empty spin, so it cannot threshold a single iteration. Counting spins
 * reuses the PAUSE mechanism POLL-005 already established (no new syscall,
 * freestanding-safe). */
static void srvpoll_backoff_pause_n(u64 n) {
  for (u64 i = 0; i < n; i++) __builtin_ia32_pause();
}

i64 wired_srvpoll_spin_step_backoff(
    i64 fd, quic_mmsg_buf* bufs, usz count, wired_srvpoll_backoff* bo) {
  i64 r = wired_udp_recvmmsg_nowait(fd, bufs, count);
  if (r > 0) {
    bo->empty_spins = 0;
    return r;
  }
  if (bo->empty_spins < WIRED_SRVPOLL_BACKOFF_MAX) bo->empty_spins++;
  srvpoll_backoff_pause_n(bo->empty_spins);
  return r;
}
