#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

static int gcmx86_cpuid_ok(void);

/* CPUID.1:ECX bit 25 (AES-NI), bit 1 (PCLMULQDQ) and bit 9 (SSSE3, for
 * the byte reversal; every CPU with AES-NI has it, checked all the same). */
static int gcmx86_cpuid_ok(void) {
  u32 c = wired_arch_cpuid_ecx(1u);
  return (int)((c >> 25) & (c >> 1) & (c >> 9) & 1u);
}

/* 0 unknown, 1 unsupported, 2 supported. File scope so a test can pin 1 and
 * run gcm_seal/gcm_open's scalar fallback on an AES-NI host. */
static int gcmx86_cached;

int gcmx86_supported(void) {
  if (gcmx86_cached == 0) {
    gcmx86_cached = 1 + gcmx86_cpuid_ok();
  }
  return gcmx86_cached - 1;
}
