#include "app/http3/server/srvpin/srvpin.h"

#include "common/platform/sys/syscall.h"

/* glibc's cpu_set_t is 128 bytes (1024 CPUs); matching that size is more than
 * this SDK will ever see and keeps sched_getaffinity's in/out cpusetsize
 * simple (man 2 sched_getaffinity: the kernel writes up to cpusetsize bytes
 * and returns the number of bytes actually written). */
#define WIRED_SRVPIN_MASK_BYTES 128
/* PIN-002: CPUs 0-63 fit in one 8-byte unsigned long; sched_setaffinity only
 * needs that much for this SDK's target machines. */
#define WIRED_SRVPIN_SETMASK_BYTES 8

/* Count set bits across n bytes (PIN-003: popcount over the affinity mask
 * rather than parsing /sys). Split out so the two nested loops don't push the
 * caller over CCN 3. */
static int srvpin_popcount_bytes(const u8* p, usz n) {
  int cnt = 0;
  for (usz i = 0; i < n; i++)
    for (u8 b = p[i]; b; b >>= 1) cnt += (int)(b & 1);
  return cnt;
}

int wired_srvpin_cpu_count(void) {
  u8  mask[WIRED_SRVPIN_MASK_BYTES] = {0};
  i64 r = syscall3(SYS_sched_getaffinity, 0, WIRED_SRVPIN_MASK_BYTES, mask);
  if (r < 0) return (int)r;
  return srvpin_popcount_bytes(mask, WIRED_SRVPIN_MASK_BYTES);
}

/* 1 iff cpu_index is a valid bit position in the 8-byte setaffinity mask. */
static int srvpin_cpu_index_valid(int cpu_index) {
  return cpu_index >= 0 && cpu_index < WIRED_SRVPIN_SETMASK_BYTES * 8;
}

int wired_srvpin_bind_self(int cpu_index) {
  u64 mask;
  if (!srvpin_cpu_index_valid(cpu_index)) return -1;
  mask = (u64)1 << cpu_index;
  return (int)syscall3(
      SYS_sched_setaffinity, 0, WIRED_SRVPIN_SETMASK_BYTES, &mask);
}
