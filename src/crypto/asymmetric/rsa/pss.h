#ifndef RSA_PSS_H
#define RSA_PSS_H

#include "common/bytes/span/span.h"
#include "crypto/asymmetric/rsa/mgf1.h"

/** RSASSA-PSS parameters (RFC 8017 9.1): digest h serves both as the
 * message hash and inside MGF1; salt_len is sLen. */
typedef struct {
  rsa_digest h;
  usz        salt_len;
} rsa_pss_cfg;

/* RFC 8017 9.1.2. EMSA-PSS-VERIFY under cfg. em is the encoded message;
 * em_bits is the modulus bit length minus 1; mhash is the cfg->h.len-octet
 * message digest. em is at most 512 octets. Returns 1 on consistent, else
 * 0. */
int emsa_pss_verify(
    wired_span em, usz em_bits, wired_span mhash, const rsa_pss_cfg* cfg);

#endif
