#include "crypto/symmetric/aead/gcmx86/gcmx86_impl.h"

usz gcmx86_seal(
    const gcmx86* x,
    const u8      nonce[GCMX86_NONCE],
    wired_span    aad,
    wired_span    pt,
    u8*           out) {
  u8 j0[16], j[16];
  gcmx86_j0(j0, nonce);
  for (usz i = 0; i < 16; i++) j[i] = j0[i];
  gcmx86_ctr(x, j, pt, out);
  gcmx86_tag(x, j0, aad, wired_span_of(out, pt.n), out + pt.n);
  return pt.n + GCMX86_TAG;
}

usz gcmx86_open(
    const gcmx86* x,
    const u8      nonce[GCMX86_NONCE],
    wired_span    aad,
    wired_span    ct,
    u8*           out) {
  u8 j[16], want[16];
  if (ct.n < GCMX86_TAG) return 0;
  wired_span body = wired_span_of(ct.p, ct.n - GCMX86_TAG);
  gcmx86_j0(j, nonce);
  gcmx86_tag(x, j, aad, body, want);
  if (ct_diff16(want, ct.p + body.n) != 0)
    return 0; /* reject: leave out untouched */
  gcmx86_ctr(x, j, body, out);
  return body.n;
}
