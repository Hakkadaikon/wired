#ifndef SRESET_SRESET_H
#define SRESET_SRESET_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.3 stateless reset. An endpoint derives a 16-byte Stateless
 * Reset Token for each connection ID it issues, advertising it; a peer that
 * has lost state sends a packet ending in that token to signal the
 * connection is gone. Detection compares a received datagram's trailing 16
 * bytes against the expected token in constant time. */

#define SRESET_TOKEN 16
#define SRESET_KEY 32 /* static per-endpoint reset secret */

/* RFC 9000 10.3.2: the reset key must be static across restarts, or a
 * rebooted server cannot produce the token it advertised before the reboot
 * -- the whole point of a stateless reset. Derive the per-endpoint key from
 * a long-lived secret (the certificate seed) rather than per-boot
 * randomness. */
void sreset_key_derive(const u8 secret[SRESET_KEY], u8 key[SRESET_KEY]);

/* Derive the Stateless Reset Token for a connection ID under a static
 * per-endpoint key (HMAC-SHA256 truncated to 16 bytes). */
void sreset_token(
    const u8  key[SRESET_KEY],
    const u8* cid,
    usz       cid_len,
    u8        token[SRESET_TOKEN]);

/* Whether a received datagram of `len` bytes is a stateless reset carrying
 * the expected token: its trailing 16 bytes match, in constant time, and the
 * datagram is long enough to contain a token. Returns 1 on a match. */
int sreset_detect(const u8* dgram, usz len, const u8 token[SRESET_TOKEN]);

/* Smallest packet that can carry a token: 5 bytes of header room (enough to
 * look like a short header, RFC 9000 10.3) plus the 16-byte token. */
#define SRESET_MIN (5 + SRESET_TOKEN)

/* RFC 9000 10.3: the size to send for a stateless reset triggered by a
 * received packet of `trigger_len` bytes. An endpoint SHOULD NOT send a
 * reset that is three or more times the size of the triggering packet (to
 * avoid being used for amplification), and MUST be at least
 * SRESET_MIN bytes to look like a valid short header. */
usz sreset_size(usz trigger_len);

/* Build a stateless reset packet for `cid` into `out` (capacity `out_cap`).
 * Size is sreset_size(trigger_len), clamped to out_cap. The leading
 * bytes are random (via `rand_fill`, e.g. rng_bytes) and the trailing
 * 16 bytes are the token derived from `key`+`cid`. Writes the packet length
 * to *out_len. Returns 1 on success, 0 if out_cap is below the minimum. */
int sreset_build(
    const u8  key[SRESET_KEY],
    const u8* cid,
    usz       cid_len,
    usz       trigger_len,
    int (*rand_fill)(u8* buf, usz len),
    u8*  out,
    usz  out_cap,
    usz* out_len);

#endif
