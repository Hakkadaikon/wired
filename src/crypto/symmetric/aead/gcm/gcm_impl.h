#ifndef CRYPTO_SYMMETRIC_AEAD_GCM_GCM_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_GCM_GCM_IMPL_H

/* Internal to the gcm*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/be.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/gcm/gcm.h"
#include "crypto/symmetric/aead/gcm/gcm256.h"
#include "crypto/symmetric/aead/gcmx86/gcmx86.h"

/* AES-NI/PCLMULQDQ dispatch for AES-128-GCM (RFC 9001 5.3 uses the same AEAD
 * regardless of which block-cipher backend computes it). Nonce/tag sizes
 * must agree between the two paths for the dispatch below to be transparent. */
_Static_assert(GCM_NONCE == GCMX86_NONCE, "gcm/gcmx86 nonce size");

_Static_assert(GCM_TAG == GCMX86_TAG, "gcm/gcmx86 tag size");

/* AES-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const aes128* a;
  u8            ctr[16];
} gcm_ctr;

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const gcm_ctx* g;
  u8             h[16];
  u8             j0[16];
} gcm_st;

/* AES-256-GCM (RFC 8446 Appendix B.4, 0x1302). Same mode of operation as
 * AES-128-GCM above; only the block cipher call (aes256_encrypt) and
 * the types carrying it differ. GHASH/counter helpers (gcm_ghash_bytes,
 * gcm_ghash_block, gcm_ctr_inc, gcm_put_be64) are shared, not duplicated. */

/* AES-256-CTR keystream state: key schedule plus the running counter block. */
typedef struct {
  const aes256* a;
  u8            ctr[16];
} gcm256_ctr;

/* Per-invocation GHASH state: the inputs plus H = E(K, 0^128) and J0. */
typedef struct {
  const gcm256_ctx* g;
  u8                h[16];
  u8                j0[16];
} gcm256_st;

void gcm_xor16(u8* dst, const u8* src);
void gcm_gf_mul(const u8 x[16], const u8 y[16], u8 z[16]);
void gcm_ghash_block(const u8 h[16], u8 y[16], const u8* block);
void gcm_ghash_bytes(const u8 h[16], u8 y[16], const u8* p, usz len);
void gcm_put_be64(u8* p, u64 v);
void gcm_ctr_inc(u8 c[16]);
void gcm_ctr_xor(gcm_ctr* c, wired_span in, u8* out);
void gcm_setup(const gcm_ctx* g, gcm_st* st);

#endif
