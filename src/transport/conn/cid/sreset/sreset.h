#ifndef QUIC_SRESET_SRESET_H
#define QUIC_SRESET_SRESET_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.3 stateless reset. An endpoint derives a 16-byte Stateless
 * Reset Token for each connection ID it issues, advertising it; a peer that
 * has lost state sends a packet ending in that token to signal the
 * connection is gone. Detection compares a received datagram's trailing 16
 * bytes against the expected token in constant time. */

#define QUIC_SRESET_TOKEN 16
#define QUIC_SRESET_KEY   32 /* static per-endpoint reset secret */

/* Derive the Stateless Reset Token for a connection ID under a static
 * per-endpoint key (HMAC-SHA256 truncated to 16 bytes). */
void quic_sreset_token(const u8 key[QUIC_SRESET_KEY],
                       const u8 *cid, usz cid_len,
                       u8 token[QUIC_SRESET_TOKEN]);

/* Whether a received datagram of `len` bytes is a stateless reset carrying
 * the expected token: its trailing 16 bytes match, in constant time, and the
 * datagram is long enough to contain a token. Returns 1 on a match. */
int quic_sreset_detect(const u8 *dgram, usz len,
                       const u8 token[QUIC_SRESET_TOKEN]);

#endif
