#ifndef QUIC_RETRYTOKEN_RETRYTOKEN_H
#define QUIC_RETRYTOKEN_RETRYTOKEN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 8.1.1/8.1.2: a server validates a client's address by sending a
 * Retry token the client must echo. The token binds the client's address and
 * the original destination connection ID under a server-only key (HMAC), so
 * the server can verify it statelessly without trusting the client. */

#define QUIC_RETRYTOKEN_LEN 32 /* HMAC-SHA256 output */
#define QUIC_RETRYTOKEN_KEY 32

/* The client address and original DCID bound into a Retry token. */
typedef struct {
  quic_span addr;
  quic_span odcid;
} quic_retrytoken_in;

/* Generate a Retry token for a client address and original DCID under the
 * server key. */
void quic_retrytoken_make(
    const u8 key[QUIC_RETRYTOKEN_KEY],
    const quic_retrytoken_in *in,
    u8 token[QUIC_RETRYTOKEN_LEN]);

/* Validate a presented token: it must equal the token the server would have
 * generated for this address and original DCID. Constant-time. Returns 1 if
 * valid. */
int quic_retrytoken_verify(
    const u8 key[QUIC_RETRYTOKEN_KEY],
    const quic_retrytoken_in *in,
    const u8 token[QUIC_RETRYTOKEN_LEN]);

#endif
