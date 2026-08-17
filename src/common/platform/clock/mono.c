#include "common/platform/clock/mono.h"

#include "common/platform/clock/clock.h"

/* Linux clockid for CLOCK_MONOTONIC (uapi/linux/time.h). */
#define CLOCK_MONOTONIC 1

u64 clock_mono_ms(void) {
  timespec ts = {0};
  if (wired_arch_clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
  return (u64)ts.sec * 1000u + (u64)ts.nsec / 1000000u;
}
