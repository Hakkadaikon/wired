#ifndef QUIC_RSA_RSA_VERIFY_H
#define QUIC_RSA_RSA_VERIFY_H

#include "common/bytes/span/span.h"

/* RSA public key: modulus n and exponent e, both big-endian. */
typedef struct {
  quic_span n;
  quic_span e;
} quic_rsa_pub;

/* RFC 8017: this verifier supports the common public exponent F4 (65537)
 * only. 1 if e (canonical big-endian) is exactly 65537. */
int quic_rsa_e_is_f4(const u8* e, usz e_len);

/* RFC 8017 8.2.2. RSASSA-PKCS1-v1_5 verification with SHA-256/384/512
 * (selected by msg_hash.n: 32, 48, or 64). sig is big-endian; pub->e must
 * be F4 (anything else is rejected). Returns 1 if the signature is valid,
 * else 0. */
int quic_rsa_pkcs1_verify(
    const quic_rsa_pub* pub, quic_span sig, quic_span msg_hash);

#endif
