#ifndef QUIC_RSA_PSS_H
#define QUIC_RSA_PSS_H

#include "sys/syscall.h"

/* RFC 8017 9.1.2. EMSA-PSS-VERIFY with SHA-256 and salt length 32. em is the
 * encoded message of em_len octets; em_bits is the modulus bit length minus 1;
 * mhash is the 32-byte SHA-256 digest of the message. Returns 1 on consistent,
 * else 0. */
int quic_emsa_pss_verify(const u8 *em, usz em_len, usz em_bits,
                         const u8 *mhash, usz hash_len);

#endif
