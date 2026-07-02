#include "crypto/asymmetric/rsa/mgf1.h"

#include "common/bytes/util/be.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* SHA-256(seed || counter_be32) -> 32-byte block. */
static void mgf1_block(quic_span seed, u32 counter, u8 out[32]) {
  u8 c[4];
  quic_put_be32(c, counter);
  quic_sha256_ctx s;
  quic_sha256_init(&s);
  quic_sha256_update(&s, seed.p, seed.n);
  quic_sha256_update(&s, c, 4);
  quic_sha256_final(&s, out);
}

static usz min_usz(usz a, usz b) { return a < b ? a : b; }

/* RFC 8017 B.2.1. */
void quic_mgf1_sha256(quic_span seed, quic_mspan mask) {
  u8  t[32];
  usz off = 0;
  for (u32 counter = 0; off < mask.n; counter++) {
    mgf1_block(seed, counter, t);
    usz n = min_usz(mask.n - off, 32);
    for (usz i = 0; i < n; i++) mask.p[off + i] = t[i];
    off += n;
  }
}
