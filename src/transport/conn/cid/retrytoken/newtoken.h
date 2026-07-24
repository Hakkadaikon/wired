#ifndef QUIC_RETRYTOKEN_NEWTOKEN_H
#define QUIC_RETRYTOKEN_NEWTOKEN_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 8.1.3: a server may send a NEW_TOKEN frame after the handshake so
 * a future connection can skip address validation. Unlike a Retry token
 * (bound only to the address and ODCID of one handshake in progress), a
 * NEW_TOKEN token must remain valid across a real time gap, so it carries:
 *
 *   issued_at (8 bytes, UNIX epoch seconds) || nonce (16 bytes, CSPRNG) ||
 *   HMAC-SHA256(key, addr || issued_at || nonce) (32 bytes)
 *
 * The random nonce makes every issued token unique (8.1.3 "MUST ensure that
 * ... tokens ... are unique", satisfied with overwhelming probability by 128
 * random bits per token, the same construction used for connection IDs and
 * PATH_CHALLENGE data elsewhere in this SDK); issued_at bounds its lifetime
 * (8.1.3 "SHOULD ensure that tokens expire"); the HMAC binds both to the
 * presenting address and covers the whole token with integrity protection,
 * so a modified token is rejected (8.1.4). Replay limiting (8.1.4) is a
 * single-use check the caller performs over the nonce field, e.g. with
 * quic_zerortt_seen_check (transport/conn/loop/manage/zerortt_seen.h) -- the
 * nonce is already a fresh unique identity per token, so no new data
 * structure is needed for that check. */

#define QUIC_NEWTOKEN_KEY 32   /* HMAC-SHA256 key */
#define QUIC_NEWTOKEN_NONCE 16 /* CSPRNG bytes making each token unique */
#define QUIC_NEWTOKEN_MAC 32   /* HMAC-SHA256 output */
#define QUIC_NEWTOKEN_WIRE_LEN (8 + QUIC_NEWTOKEN_NONCE + QUIC_NEWTOKEN_MAC)

/* RFC 9000 8.1.3 leaves the exact lifetime to the implementation ("SHOULD
 * ensure that tokens expire ... limiting their usefulness to an attacker").
 * 7 days is short enough to bound a leaked token's usefulness while long
 * enough that a returning client's address-validation skip remains useful
 * across a typical revisit interval. */
#define QUIC_NEWTOKEN_MAX_AGE_SECS (7ULL * 24 * 3600)

/* Generate a NEW_TOKEN wire token bound to addr, issued at now_secs, with a
 * fresh random nonce (so repeated calls -- even for the same address and
 * timestamp -- never produce the same token). Writes exactly
 * QUIC_NEWTOKEN_WIRE_LEN bytes to token. Returns 1 on success, 0 if the
 * CSPRNG failed. */
int quic_newtoken_wire_make(
    const u8  key[QUIC_NEWTOKEN_KEY],
    quic_span addr,
    u64       now_secs,
    u8        token[QUIC_NEWTOKEN_WIRE_LEN]);

/* Verify a presented wire token against the presenting address and current
 * time. Accepts only if: the token is exactly QUIC_NEWTOKEN_WIRE_LEN bytes,
 * its HMAC matches (constant-time), and now_secs is within
 * QUIC_NEWTOKEN_MAX_AGE_SECS of the token's issued_at (RFC 9000 8.1.3
 * expiry; a token from the future, e.g. a manipulated timestamp, is also
 * rejected). On success returns 1 and sets *issued_at and *nonce (a view
 * into token, for the caller's own replay check). Returns 0 otherwise. */
int quic_newtoken_wire_verify(
    const u8   key[QUIC_NEWTOKEN_KEY],
    quic_span  addr,
    quic_span  token,
    u64        now_secs,
    u64*       issued_at,
    quic_span* nonce);

#endif
