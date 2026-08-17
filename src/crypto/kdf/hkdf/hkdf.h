#ifndef QUIC_HKDF_HKDF_H
#define QUIC_HKDF_HKDF_H

#include "crypto/symmetric/hash/hash/hmac.h"

/**
 * @file
 * RFC 5869 HKDF over HMAC-SHA-256, plus the TLS 1.3 / QUIC
 * HKDF-Expand-Label construction (RFC 8446 7.1, RFC 9001 5.1).
 */

/** pseudorandom key length */
#define QUIC_HKDF_PRK QUIC_SHA256_DIGEST

/** pseudorandom key length for the SHA-384 instantiation */
#define QUIC_HKDF_PRK_384 QUIC_SHA384_DIGEST

/**
 * HkdfLabel inputs (RFC 8446 7.1): the label (without the "tls13 " prefix)
 * and the context (may be empty: {0, 0}).
 */
typedef struct {
  const char* label;     /**< label text without the "tls13 " prefix */
  usz         label_len; /**< length of label in bytes */
  wired_span  ctx;       /**< context (hash value); may be empty {0, 0} */
} quic_hkdf_label;

/**
 * prk = HKDF-Extract(salt, ikm).
 *
 * @param salt optional salt (may be empty)
 * @param ikm  input keying material
 * @param prk  receives the 32-byte pseudorandom key
 */
void quic_hkdf_extract(wired_span salt, wired_span ikm, u8 prk[QUIC_HKDF_PRK]);

/**
 * okm = HKDF-Expand(prk, info, okm.n).
 *
 * okm.n must be <= 255*32.
 *
 * @param prk  32-byte pseudorandom key from quic_hkdf_extract()
 * @param info context/application-specific info (may be empty)
 * @param okm  receives exactly okm.n bytes of output keying material
 * @return 1 on success, 0 if the length is out of range.
 */
int quic_hkdf_expand(
    const u8 prk[QUIC_HKDF_PRK], wired_span info, wired_mspan okm);

/**
 * okm = HKDF-Expand-Label(prk, label, context, okm.n) with the "tls13 "
 * prefix.
 *
 * @param prk 32-byte pseudorandom key
 * @param l   label and context inputs (see quic_hkdf_label)
 * @param okm receives exactly okm.n bytes of output keying material
 * @return 1 on success, 0 if the label/context/length do not fit.
 */
int quic_hkdf_expand_label(
    const u8 prk[QUIC_HKDF_PRK], const quic_hkdf_label* l, wired_mspan okm);

/**
 * prk = HKDF-Extract(salt, ikm) instantiated with HMAC-SHA-384
 * (RFC 5869 2.2, TLS_AES_256_GCM_SHA384).
 *
 * @param salt optional salt (may be empty)
 * @param ikm  input keying material
 * @param prk  receives the 48-byte pseudorandom key
 */
void quic_hkdf_extract_384(
    wired_span salt, wired_span ikm, u8 prk[QUIC_HKDF_PRK_384]);

/**
 * okm = HKDF-Expand(prk, info, okm.n) instantiated with HMAC-SHA-384
 * (RFC 5869 2.3).
 *
 * okm.n must be <= 255*48.
 *
 * @param prk  48-byte pseudorandom key from quic_hkdf_extract_384()
 * @param info context/application-specific info (may be empty)
 * @param okm  receives exactly okm.n bytes of output keying material
 * @return 1 on success, 0 if the length is out of range.
 */
int quic_hkdf_expand_384(
    const u8 prk[QUIC_HKDF_PRK_384], wired_span info, wired_mspan okm);

/**
 * okm = HKDF-Expand-Label(prk, label, context, okm.n) with the "tls13 "
 * prefix, instantiated with HMAC-SHA-384 (RFC 8446 7.1, RFC 9001 5.1).
 *
 * @param prk 48-byte pseudorandom key
 * @param l   label and context inputs (see quic_hkdf_label)
 * @param okm receives exactly okm.n bytes of output keying material
 * @return 1 on success, 0 if the label/context/length do not fit.
 */
int quic_hkdf_expand_label_384(
    const u8 prk[QUIC_HKDF_PRK_384], const quic_hkdf_label* l, wired_mspan okm);

#endif
