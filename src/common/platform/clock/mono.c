#include "common/platform/clock/mono.h"

#include "common/platform/clock/clock.h"

/* Linux clockid for CLOCK_MONOTONIC (uapi/linux/time.h). */
#define QUIC_CLOCK_MONOTONIC 1

u64 quic_clock_mono_ms(void) {
  quic_timespec ts = {0};
  if (syscall3(SYS_clock_gettime, QUIC_CLOCK_MONOTONIC, &ts, 0) != 0) return 0;
  return (u64)ts.sec * 1000u + (u64)ts.nsec / 1000000u;
}
