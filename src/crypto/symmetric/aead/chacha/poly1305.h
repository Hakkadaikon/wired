#ifndef QUIC_CHACHA_POLY1305_H
#define QUIC_CHACHA_POLY1305_H

#include "common/platform/sys/syscall.h"

/* RFC 8439 2.5 Poly1305 one-time authenticator. 32-byte key, 16-byte tag. */

#define QUIC_POLY1305_KEY 32
#define QUIC_POLY1305_TAG 16

void quic_poly1305(
    const u8  key[QUIC_POLY1305_KEY],
    const u8 *msg,
    usz       len,
    u8        tag[QUIC_POLY1305_TAG]);

#endif
