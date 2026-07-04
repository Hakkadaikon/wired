#ifndef QUIC_RETRYDRIVE_TOKEN_H
#define QUIC_RETRYDRIVE_TOKEN_H

#include "common/platform/sys/syscall.h"
#include "transport/conn/cid/retrydrive/reconnect.h"

/* RFC 9000 17.2.5.1: a client's Initial after an accepted Retry carries the
 * Retry token; before any Retry the token is empty. Sets *token / *len to the
 * stored token when a Retry was accepted, else *len = 0 (empty token). */
void quic_retrydrive_initial_token(
    const quic_retrydrive_state* s, const u8** token, usz* len);

#endif
