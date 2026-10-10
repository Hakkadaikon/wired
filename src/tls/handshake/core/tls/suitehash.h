#ifndef TLS_SUITEHASH_H
#define TLS_SUITEHASH_H

#include "crypto/kdf/hkdf/hkdf.h"

/** @file
 * RFC 8446 B.4 / 7.1: the hash a TLS 1.3 cipher suite runs its key schedule,
 * transcript and Finished MAC over (SHA-256 for 0x1301/0x1303, SHA-384 for
 * 0x1302). Every secret is Hash.length bytes. */

/** Largest Hash.length of any supported suite (SHA-384). */
#define TLS_HASH_MAX HKDF_PRK_384

/** One suite's hash and the HKDF/HMAC instantiated over it. */
typedef struct {
  usz len; /**< Hash.length in bytes (32 or 48) */
  /** one-shot digest of n bytes at p into out (len bytes) */
  void (*digest)(const u8* p, usz n, u8* out);
  /** HKDF-Extract(salt, ikm) into prk (len bytes) */
  void (*extract)(wired_span salt, wired_span ikm, u8* prk);
  /** HKDF-Expand-Label(prk, l, okm.n) */
  int (*expand_label)(const u8* prk, const hkdf_label* l, wired_mspan okm);
  /** HMAC(key, msg) into out (len bytes) */
  void (*mac)(wired_span key, wired_span msg, u8* out);
} tls_hash;

/** The hash for suite: SHA-384 for TLS_AES_256_GCM_SHA384, SHA-256 for
 * every other value (including 0, the default of a zeroed struct).
 * @param suite RFC 8446 B.4 cipher suite code point
 * @return the suite's hash descriptor (never NULL). */
const tls_hash* tls_hash_of(u16 suite);

#endif
