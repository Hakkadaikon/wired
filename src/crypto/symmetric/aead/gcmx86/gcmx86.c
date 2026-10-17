#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

static int gcmx86_cpuid_ok(void);

/* CPUID.1:ECX bit 25 (AES-NI) and bit 1 (PCLMULQDQ). */
static int gcmx86_cpuid_ok(void) {
  u32 c = wired_arch_cpuid_ecx(1u);
  return (int)((c >> 25) & (c >> 1) & 1u);
}

int gcmx86_supported(void) {
  static int cached; /* 0 unknown, 1 unsupported, 2 supported */
  if (cached == 0) {
    cached = 1 + gcmx86_cpuid_ok();
  }
  return cached - 1;
}
