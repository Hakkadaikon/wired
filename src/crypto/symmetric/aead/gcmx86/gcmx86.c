#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

int gcmx86_cached;

/* Only a successful probe is cached: a failed one (on aarch64 the auxv open
 * can fail transiently, e.g. EMFILE) is retried on the next call instead of
 * pinning the software path. Concurrent first calls race benignly: every
 * writer stores the same 2. */
int gcmx86_supported(void) {
  if (gcmx86_cached == 0 && wired_arch_aes_clmul_ok()) {
    gcmx86_cached = 2;
  }
  return gcmx86_cached == 2;
}
