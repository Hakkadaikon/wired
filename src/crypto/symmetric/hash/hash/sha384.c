#include "crypto/symmetric/hash/hash/sha384.h"

/* FIPS 180-4 5.3.4: the SHA-384 initial hash value. */
static const u64 sha384_h0[8] = {0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
                                 0x9159015a3070dd17, 0x152fecd8f70e5939,
                                 0x67332667ffc00b31, 0x8eb44a8768581511,
                                 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};

void quic_sha384_init(quic_sha512_ctx* s) {
  quic_sha512_init(s);
  for (usz i = 0; i < 8; i++) s->h[i] = sha384_h0[i];
}

void quic_sha384_final(quic_sha512_ctx* s, u8 out[QUIC_SHA384_DIGEST]) {
  u8 full[QUIC_SHA512_DIGEST];
  quic_sha512_final(s, full);
  for (usz i = 0; i < QUIC_SHA384_DIGEST; i++) out[i] = full[i];
}

void quic_sha384(const u8* data, usz len, u8 out[QUIC_SHA384_DIGEST]) {
  quic_sha512_ctx s;
  quic_sha384_init(&s);
  quic_sha512_update(&s, data, len);
  quic_sha384_final(&s, out);
}
