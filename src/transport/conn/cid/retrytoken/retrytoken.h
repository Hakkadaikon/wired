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
    const u8                  key[QUIC_RETRYTOKEN_KEY],
    const quic_retrytoken_in* in,
    u8                        token[QUIC_RETRYTOKEN_LEN]);

/* Validate a presented token: it must equal the token the server would have
 * generated for this address and original DCID. Constant-time. Returns 1 if
 * valid. */
int quic_retrytoken_verify(
    const u8                  key[QUIC_RETRYTOKEN_KEY],
    const quic_retrytoken_in* in,
    const u8                  token[QUIC_RETRYTOKEN_LEN]);

/* Longest wire token: odcid_len(1) + a 20-byte ODCID + the HMAC. */
#define QUIC_RETRYTOKEN_WIRE_MAX (1 + 20 + QUIC_RETRYTOKEN_LEN)

/* Build the wire token a Retry packet carries: odcid_len(1) || odcid ||
 * HMAC(key, addr || odcid). The HMAC alone is not invertible, so the ODCID
 * rides along in the clear -- verification recovers it statelessly for the
 * original_destination_connection_id transport parameter (RFC 9000 7.3;
 * the token's authenticity still rests entirely on the HMAC). Returns bytes
 * written (1 + odcid.n + QUIC_RETRYTOKEN_LEN), or 0 when odcid exceeds 20
 * bytes. */
usz quic_retrytoken_wire_make(
    const u8  key[QUIC_RETRYTOKEN_KEY],
    quic_span addr,
    quic_span odcid,
    u8        token[QUIC_RETRYTOKEN_WIRE_MAX]);

/* Verify a presented wire token against the presenting address. On success
 * returns 1 and sets *odcid to the embedded ODCID (a view into token).
 * Returns 0 on a malformed token (bad length framing) or an HMAC mismatch.
 * Constant-time in the HMAC compare. */
int quic_retrytoken_wire_verify(
    const u8   key[QUIC_RETRYTOKEN_KEY],
    quic_span  addr,
    quic_span  token,
    quic_span* odcid);

#endif
