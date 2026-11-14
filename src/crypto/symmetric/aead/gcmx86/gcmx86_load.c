#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

/* XOR the final partial block (in.n < 16) with the keystream of counter
 * block blk. */
void gcmx86_ctr_tail(const gcmx86* x, gcmx86_v blk, wired_span in, u8* out) {
  u8 ks[16];
  gcmx86_store(ks, gcmx86_aes(x, blk));
  for (usz i = 0; i < in.n; i++) {
    out[i] = in.p[i] ^ ks[i];
  }
}

void gcmx86_ecb(const gcmx86* x, const u8 in[16], u8 out[16]) {
  gcmx86_store(out, gcmx86_aes(x, gcmx86_load(in)));
}
