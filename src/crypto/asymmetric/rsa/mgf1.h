#ifndef RSA_MGF1_H
#define RSA_MGF1_H

#include "common/bytes/span/span.h"

/* The longest supported digest (SHA-512). */
#define RSA_DIGEST_MAX 64

/** A one-shot hash: fn digests (in, n) into out, len octets long
 * (<= RSA_DIGEST_MAX). */
typedef struct {
  void (*fn)(const u8*, usz, u8*);
  usz len;
} rsa_digest;

/* RFC 8017 B.2.1. MGF1 mask generation over digest h. Fills mask from seed.
 * Returns 0 (mask untouched) when seed or h.len exceeds RSA_DIGEST_MAX. */
int rsa_mgf1(rsa_digest h, wired_span seed, wired_mspan mask);

#endif
