#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

/* Advance the counter and XOR the final partial block (in.n < 16). */
void gcmx86_ctr_tail(const gcmx86* x, u8 j[16], wired_span in, u8* out) {
  u8 ks[16];
  gcmx86_inc32(j);
  gcmx86_store(ks, gcmx86_aes(x, gcmx86_load(j)));
  for (usz i = 0; i < in.n; i++) {
    out[i] = in.p[i] ^ ks[i];
  }
}
