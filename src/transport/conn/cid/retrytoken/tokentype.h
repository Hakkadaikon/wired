#ifndef QUIC_RETRYTOKEN_TOKENTYPE_H
#define QUIC_RETRYTOKEN_TOKENTYPE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 8.1.1/8.1.3: a token a client sends in an Initial may come from a
 * Retry (address validation, must be present) or from a NEW_TOKEN frame (a
 * future-use token). A server processes the two differently, so it must tell
 * them apart. We prefix the token body with one type-tag byte. */

#define QUIC_TOKEN_TAG_RETRY    0x01
#define QUIC_TOKEN_TAG_NEWTOKEN 0x02

/* Write a tagged token: tag byte + body (body_len bytes) into out (cap total).
 * Returns total bytes written, or 0 if it does not fit. */
usz quic_token_tag_retry(u8 *out, usz cap, const u8 *body, usz body_len);
usz quic_token_tag_newtoken(u8 *out, usz cap, const u8 *body, usz body_len);

/* True if token (len bytes) is a non-empty Retry-tagged token. */
int quic_token_is_retry(const u8 *token, usz len);

#endif
