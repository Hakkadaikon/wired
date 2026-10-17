#ifndef CRYPTO_SYMMETRIC_AEAD_GCMX86_GCMX86_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_GCMX86_GCMX86_IMPL_H

/* Internal to the gcmx86*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/arch/x8664/simd128.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/ct.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "crypto/symmetric/aead/gcmx86/gcmx86.h"

/* AES-128-GCM per NIST SP 800-38D on x86-64 AES-NI + PCLMULQDQ. The
 * instruction wrappers live in the arch adapter (simd128.h); this file is
 * only the GCM math on top of them. */

/* One SSE register: u8 lanes for load/store/XOR, u32 lanes for the GHASH
 * shift arithmetic (casts between same-size vector types reinterpret bits).
 */
typedef wired_arch_v128 gcmx86_v;

typedef wired_arch_v128w gcmx86_w;

gcmx86_v gcmx86_load(const u8* p);
void     gcmx86_store(u8* p, gcmx86_v v);
gcmx86_v gcmx86_load_rev(const u8* p, usz n);
gcmx86_v gcmx86_rev(gcmx86_v a);
gcmx86_v gcmx86_aes(const gcmx86* x, gcmx86_v in);
gcmx86_v gcmx86_gfmul(gcmx86_v a, gcmx86_v b);
gcmx86_v gcmx86_ghash(gcmx86_v h, gcmx86_v y, wired_span in);
void     gcmx86_inc32(u8 j[16]);
void     gcmx86_ctr_block(const gcmx86* x, u8 j[16], const u8* in, u8* out);
void     gcmx86_ctr_tail(const gcmx86* x, u8 j[16], wired_span in, u8* out);
void     gcmx86_ctr(const gcmx86* x, u8 j[16], wired_span in, u8* out);
void     gcmx86_j0(u8 j[16], const u8 nonce[GCMX86_NONCE]);
void     gcmx86_tag(
    const gcmx86* x,
    const u8      j0[16],
    wired_span    aad,
    wired_span    ct,
    u8            tag[16]);

#endif
