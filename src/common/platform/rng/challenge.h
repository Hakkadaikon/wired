#ifndef QUIC_RNG_CHALLENGE_H
#define QUIC_RNG_CHALLENGE_H

#include "common/platform/sys/syscall.h"

/* PATH_CHALLENGE data (RFC 9000 8.2) and stateless reset tokens (RFC
 * 9000 10.3). */

/* Generate 8 bytes of PATH_CHALLENGE data. Returns 1 on success, 0 on RNG
 * failure. */
int quic_challenge_generate(u8 token[8]);

/* Generate a 16-byte stateless reset token. Returns 1 on success, 0 on RNG
 * failure. */
int quic_reset_token_generate(u8 token[16]);

#endif
