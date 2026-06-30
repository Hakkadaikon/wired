#include "common/platform/rng/challenge.h"

#include "common/platform/rng/rng.h"

/* RFC 9000 8.2: PATH_CHALLENGE carries 8 octets of unpredictable data. */
int quic_challenge_generate(u8 token[8]) { return quic_rng_bytes(token, 8); }

/* RFC 9000 10.3: a stateless reset token is 16 octets. */
int quic_reset_token_generate(u8 token[16]) {
  return quic_rng_bytes(token, 16);
}
