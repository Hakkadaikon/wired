#ifndef QUIC_HKDF_HKDF_H
#define QUIC_HKDF_HKDF_H

#include "crypto/symmetric/hash/hash/hmac.h"

/* RFC 5869 HKDF over HMAC-SHA-256, plus the TLS 1.3 / QUIC
 * HKDF-Expand-Label construction (RFC 8446 7.1, RFC 9001 5.1). */

#define QUIC_HKDF_PRK QUIC_SHA256_DIGEST /* pseudorandom key length */

/* prk = HKDF-Extract(salt, ikm). */
void quic_hkdf_extract(
    const u8 *salt,
    usz       salt_len,
    const u8 *ikm,
    usz       ikm_len,
    u8        prk[QUIC_HKDF_PRK]);

/* okm = HKDF-Expand(prk, info, L). L must be <= 255*32. Returns 1 on
 * success, 0 if L is out of range. */
int quic_hkdf_expand(
    const u8  prk[QUIC_HKDF_PRK],
    const u8 *info,
    usz       info_len,
    u8       *okm,
    usz       len);

/* okm = HKDF-Expand-Label(prk, label, context, L) with the "tls13 " prefix.
 * Returns 1 on success, 0 if the label/context/length do not fit. */
int quic_hkdf_expand_label(
    const u8    prk[QUIC_HKDF_PRK],
    const char *label,
    usz         label_len,
    const u8   *ctx,
    usz         ctx_len,
    u8         *okm,
    usz         len);

#endif
