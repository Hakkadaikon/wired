#ifndef QUIC_RSA_MGF1_H
#define QUIC_RSA_MGF1_H

#include "sys/syscall.h"

/* RFC 8017 B.2.1. MGF1 mask generation with SHA-256 as the hash. Fills
 * mask[0..mask_len) from seed[0..seed_len). */
void quic_mgf1_sha256(const u8 *seed, usz seed_len, u8 *mask, usz mask_len);

#endif
