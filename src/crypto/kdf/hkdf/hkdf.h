#ifndef QUIC_HKDF_HKDF_H
#define QUIC_HKDF_HKDF_H

#include "crypto/symmetric/hash/hash/hmac.h"

/* RFC 5869 HKDF over HMAC-SHA-256, plus the TLS 1.3 / QUIC
 * HKDF-Expand-Label construction (RFC 8446 7.1, RFC 9001 5.1). */

#define QUIC_HKDF_PRK QUIC_SHA256_DIGEST /* pseudorandom key length */

/* HkdfLabel inputs (RFC 8446 7.1): the label (without the "tls13 " prefix)
 * and the context (may be empty: {0, 0}). */
typedef struct {
  const char *label;
  usz         label_len;
  quic_span   ctx;
} quic_hkdf_label;

/* prk = HKDF-Extract(salt, ikm). */
void quic_hkdf_extract(quic_span salt, quic_span ikm, u8 prk[QUIC_HKDF_PRK]);

/* okm = HKDF-Expand(prk, info, okm.n). okm.n must be <= 255*32. Returns 1 on
 * success, 0 if the length is out of range. */
int quic_hkdf_expand(
    const u8 prk[QUIC_HKDF_PRK], quic_span info, quic_mspan okm);

/* okm = HKDF-Expand-Label(prk, label, context, okm.n) with the "tls13 "
 * prefix. Returns 1 on success, 0 if the label/context/length do not fit. */
int quic_hkdf_expand_label(
    const u8 prk[QUIC_HKDF_PRK], const quic_hkdf_label *l, quic_mspan okm);

#endif
