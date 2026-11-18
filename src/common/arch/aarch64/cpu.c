#if defined(__aarch64__)
#include "common/arch/aarch64/simd128.h"
#include "common/arch/sysops.h"

/* Linux auxv tag and arm64 hwcap bits (include/uapi/linux/auxvec.h,
 * arch/arm64/include/uapi/asm/hwcap.h). */
#define WIRED_ARCH_AT_HWCAP 16
#define WIRED_ARCH_HWCAP_AES_PMULL ((1ul << 3) | (1ul << 4))
#define WIRED_ARCH_AT_FDCWD (-100)

/* The AT_HWCAP value among n words of (tag, value) pairs, 0 if absent. */
static u64 wired_arch_auxv_hwcap(const u64* v, usz n) {
  for (usz i = 0; i + 1 < n; i += 2) {
    if (v[i] == WIRED_ARCH_AT_HWCAP) {
      return v[i + 1];
    }
  }
  return 0;
}

int wired_arch_aes_clmul_ok(void) {
  u64 v[128];
  i64 n;
  i64 fd = wired_arch_openat(WIRED_ARCH_AT_FDCWD, "/proc/self/auxv", 0, 0);
  if (fd < 0) {
    return 0;
  }
  n = wired_arch_read(fd, v, sizeof v);
  wired_arch_close(fd);
  return n > 0 && (wired_arch_auxv_hwcap(v, (usz)n / 8) &
                   WIRED_ARCH_HWCAP_AES_PMULL) == WIRED_ARCH_HWCAP_AES_PMULL;
}
#endif
