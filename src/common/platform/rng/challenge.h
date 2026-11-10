#ifndef RNG_CHALLENGE_H
#define RNG_CHALLENGE_H

#include "common/platform/sys/syscall.h"

/* PATH_CHALLENGE data (RFC 9000 8.2). */

/* Generate 8 bytes of PATH_CHALLENGE data. Returns 1 on success, 0 on RNG
 * failure. */
int challenge_generate(u8 token[8]);

#endif
