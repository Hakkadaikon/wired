#ifndef WIRED_ARCH_AARCH64_SIMD128_H
#define WIRED_ARCH_AARCH64_SIMD128_H

/* Only the ISA being compiled for: every header may be included (the
 * sharded test build includes them all). */
#if defined(__aarch64__)

/**
 * @file
 * 128-bit SIMD register wrappers for aarch64 (Advanced SIMD plus the ARMv8
 * Cryptographic Extension's AES and PMULL), with the semantics of the x86-64
 * adapter's instructions of the same names, so the AES-GCM code above runs
 * unchanged. Only ISA-specific crypto implementations include this.
 */

#include "common/arch/types.h"

/** One SIMD register, u8 lanes (load/store/XOR). */
typedef u8 wired_arch_v128 __attribute__((vector_size(16)));

/** One SIMD register, u32 lanes (per-lane shift arithmetic). */
typedef u32 wired_arch_v128w __attribute__((vector_size(16)));

/** One SIMD register, u64 lanes (half selection for the multiply). */
typedef u64 wired_arch_v128q __attribute__((vector_size(16)));

/** Carry-less multiply of two 64-bit values into 128 bits (PMULL). */
static inline wired_arch_v128 wired_arch_pmull(u64 x, u64 y) {
  wired_arch_v128q a = {x, 0};
  wired_arch_v128q b = {y, 0};
  wired_arch_v128  r;
  __asm__(
      ".arch_extension aes\n"
      "pmull %0.1q, %1.1d, %2.1d"
      : "=w"(r)
      : "w"(a), "w"(b));
  return r;
}

/** pclmulqdq semantics: imm bit 0 selects a's half, bit 4 b's half. */
#define WIRED_ARCH_CLMUL(a, b, imm)       \
  wired_arch_pmull(                       \
      ((wired_arch_v128q)(a))[(imm) & 1], \
      ((wired_arch_v128q)(wired_arch_v128)(b))[((imm) >> 4) & 1])

/** Whole-register byte shift toward higher lanes (pslldq): EXT of a zero
 * register and @p a, starting 16 - imm bytes in. imm is 1..15. */
#define WIRED_ARCH_VSHLB(a, imm)                                    \
  ({                                                                \
    wired_arch_v128 z_ = {0};                                       \
    wired_arch_v128 r_;                                             \
    __asm__("ext %0.16b, %1.16b, %2.16b, #%3"                       \
            : "=w"(r_)                                              \
            : "w"(z_), "w"((wired_arch_v128)(a)), "i"(16 - (imm))); \
    r_;                                                             \
  })

/** Whole-register byte shift toward lower lanes (psrldq): EXT of @p a and
 * a zero register, starting imm bytes in. imm is 1..15. */
#define WIRED_ARCH_VSHRB(a, imm)                             \
  ({                                                         \
    wired_arch_v128 z_ = {0};                                \
    wired_arch_v128 r_;                                      \
    __asm__("ext %0.16b, %1.16b, %2.16b, #%3"                \
            : "=w"(r_)                                       \
            : "w"((wired_arch_v128)(a)), "w"(z_), "i"(imm)); \
    r_;                                                      \
  })

/** One AES round with aesenc's order: AESE with a zero key does
 * AddRoundKey(0), ShiftRows and SubBytes, AESMC MixColumns, then the
 * round key. */
static inline wired_arch_v128 wired_arch_aesenc(
    wired_arch_v128 s, wired_arch_v128 rk) {
  wired_arch_v128 z = {0};
  __asm__(
      ".arch_extension aes\n"
      "aese %0.16b, %1.16b\n"
      "aesmc %0.16b, %0.16b"
      : "+w"(s)
      : "w"(z));
  return s ^ rk;
}

/** Final AES round (aesenclast): no MixColumns. */
static inline wired_arch_v128 wired_arch_aesenclast(
    wired_arch_v128 s, wired_arch_v128 rk) {
  wired_arch_v128 z = {0};
  __asm__(
      ".arch_extension aes\n"
      "aese %0.16b, %1.16b"
      : "+w"(s)
      : "w"(z));
  return s ^ rk;
}

/** Byte shuffle (TBL): lane i of the result is lane mask[i] of @p a, or 0
 * where mask[i] is 16 or more -- pshufb's result for every mask whose
 * lanes are 0..15 or have the top bit set. */
static inline wired_arch_v128 wired_arch_pshufb(
    wired_arch_v128 a, wired_arch_v128 mask) {
  wired_arch_v128 r;
  __asm__("tbl %0.16b, {%1.16b}, %2.16b" : "=w"(r) : "w"(a), "w"(mask));
  return r;
}

/** 1 when the CPU has AES and PMULL (HWCAP_AES and HWCAP_PMULL in the
 * process's auxiliary vector, read from /proc/self/auxv: cpu.c). */
int wired_arch_aes_clmul_ok(void);

#endif

#endif
