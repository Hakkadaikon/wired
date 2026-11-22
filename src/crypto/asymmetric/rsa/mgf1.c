#include "crypto/asymmetric/rsa/mgf1.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* Hash(seed || counter_be32) -> one h.len-octet block. seed.n is checked by
 * the caller to fit. */
static void mgf1_block(rsa_digest h, wired_span seed, u32 counter, u8* out) {
  u8 in[RSA_DIGEST_MAX + 4];
  bytes_memcpy(in, seed.p, seed.n);
  be_put_be32(in + seed.n, counter);
  h.fn(in, seed.n + 4, out);
}

/* h.len in [1, RSA_DIGEST_MAX] (0 wraps above it) and the seed fits. */
static int mgf1_sizes_ok(rsa_digest h, wired_span seed) {
  return seed.n <= RSA_DIGEST_MAX && h.len - 1 < RSA_DIGEST_MAX;
}

/* RFC 8017 B.2.1. */
int rsa_mgf1(rsa_digest h, wired_span seed, wired_mspan mask) {
  u8 t[RSA_DIGEST_MAX];
  if (!mgf1_sizes_ok(h, seed)) {
    return 0;
  }
  for (usz off = 0, counter = 0; off < mask.n; counter++) {
    mgf1_block(h, seed, (u32)counter, t);
    usz n = (usz)u64_min(mask.n - off, h.len);
    bytes_memcpy(mask.p + off, t, n);
    off += n;
  }
  return 1;
}
