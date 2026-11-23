#include "crypto/symmetric/aead/gcm/gcm_impl.h"

/* AES-256-GCM dispatch: AES-NI rounds and PCLMULQDQ GHASH (gcmx86 with
 * nr = 14) where the CPU has them, the software path otherwise. */

static int gcm256_x86_open_ok(wired_span ct);
static int gcm256_open_x86(const gcm256_ctx* g, wired_span ct, u8* pt);

usz gcm256_seal(const gcm256_ctx* g, wired_span pt, u8* out) {
  gcmx86 x;
  if (!gcmx86_supported()) {
    return gcm256_seal_scalar(g, pt, out);
  }
  gcmx86_init_rk(&x, g->aes->rk, AES256_ROUNDS);
  return gcmx86_seal(&x, g->nonce, g->aad, pt, out);
}

/* gcmx86_open's 0 also means an authentic empty plaintext, so a bare tag
 * takes the software path, which answers 1 for it. */
static int gcm256_x86_open_ok(wired_span ct) {
  return gcmx86_supported() && ct.n > GCM_TAG;
}

static int gcm256_open_x86(const gcm256_ctx* g, wired_span ct, u8* pt) {
  gcmx86 x;
  gcmx86_init_rk(&x, g->aes->rk, AES256_ROUNDS);
  return gcmx86_open(&x, g->nonce, g->aad, ct, pt) != 0;
}

int gcm256_open(const gcm256_ctx* g, wired_span ct, u8* pt) {
  if (ct.n < GCM_TAG) {
    return 0;
  }
  if (gcm256_x86_open_ok(ct)) {
    return gcm256_open_x86(g, ct, pt);
  }
  return gcm256_open_scalar(g, ct, pt);
}
