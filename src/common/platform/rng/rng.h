#ifndef QUIC_RNG_RNG_H
#define QUIC_RNG_RNG_H

#include "common/platform/sys/syscall.h"

/* CSPRNG via the Linux getrandom syscall. No libc. */

/* Fill buf with len cryptographically secure random bytes.
   Returns 1 when all len bytes are filled, 0 on error. */
int quic_rng_bytes(u8* buf, usz len);

#endif
