#ifndef RETRYTOKEN_RETRYTOKEN_H
#define RETRYTOKEN_RETRYTOKEN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 8.1.1/8.1.2: a server validates a client's address by sending a
 * Retry token the client must echo. The token binds the client's address and
 * the original destination connection ID under a server-only key (HMAC), so
 * the server can verify it statelessly without trusting the client. */

#define RETRYTOKEN_LEN 32 /* HMAC-SHA256 output */
#define RETRYTOKEN_KEY 32

/** The client address and original DCID bound into a Retry token. */
typedef struct {
  wired_span addr;
  wired_span odcid;
} retrytoken_in;

/* Generate a Retry token for a client address and original DCID under the
 * server key. */
void retrytoken_make(
    const u8             key[RETRYTOKEN_KEY],
    const retrytoken_in* in,
    u8                   token[RETRYTOKEN_LEN]);

/* Validate a presented token: it must equal the token the server would have
 * generated for this address and original DCID. Constant-time. Returns 1 if
 * valid. */
int retrytoken_verify(
    const u8             key[RETRYTOKEN_KEY],
    const retrytoken_in* in,
    const u8             token[RETRYTOKEN_LEN]);

/* Longest wire token: odcid_len(1) + a 20-byte ODCID + the HMAC. */
#define RETRYTOKEN_WIRE_MAX (1 + 20 + RETRYTOKEN_LEN)

/* Build the wire token a Retry packet carries: odcid_len(1) || odcid ||
 * HMAC(key, addr || odcid). The HMAC alone is not invertible, so the ODCID
 * rides along in the clear -- verification recovers it statelessly for the
 * original_destination_connection_id transport parameter (RFC 9000 7.3;
 * the token's authenticity still rests entirely on the HMAC). Returns bytes
 * written (1 + odcid.n + RETRYTOKEN_LEN), or 0 when odcid exceeds 20
 * bytes. */
usz retrytoken_wire_make(
    const u8   key[RETRYTOKEN_KEY],
    wired_span addr,
    wired_span odcid,
    u8         token[RETRYTOKEN_WIRE_MAX]);

/* Verify a presented wire token against the presenting address. On success
 * returns 1 and sets *odcid to the embedded ODCID (a view into token).
 * Returns 0 on a malformed token (bad length framing) or an HMAC mismatch.
 * Constant-time in the HMAC compare. */
int retrytoken_wire_verify(
    const u8    key[RETRYTOKEN_KEY],
    wired_span  addr,
    wired_span  token,
    wired_span* odcid);

#endif
