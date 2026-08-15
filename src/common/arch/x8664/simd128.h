#ifndef WIRED_ARCH_X8664_SIMD128_H
#define WIRED_ARCH_X8664_SIMD128_H

/**
 * @file
 * 128-bit SIMD register wrappers (x86-64 SSE/AES-NI/PCLMULQDQ). All SIMD is
 * GCC vector extensions plus inline asm for the AES/CLMUL instructions, so
 * consumers compile freestanding with no intrinsics headers. Kept separate
 * from x8664.h: only ISA-specific crypto implementations include this.
 */

#include "common/arch/types.h"

/** One SSE register, u8 lanes (load/store/XOR). Casts between same-size
 * vector types reinterpret bits. */
typedef u8 wired_arch_v128 __attribute__((vector_size(16)));

/** One SSE register, u32 lanes (per-lane shift arithmetic). */
typedef u32 wired_arch_v128w __attribute__((vector_size(16)));

/** Carry-less multiply of one 64-bit half of each operand (pclmulqdq); imm
 * bit 0 selects a's half, bit 4 selects b's half. */
#define WIRED_ARCH_CLMUL(a, b, imm)                 \
  ({                                                \
    wired_arch_v128 r_ = (a);                       \
    __asm__("pclmulqdq %2, %1, %0"                  \
            : "+x"(r_)                              \
            : "x"((wired_arch_v128)(b)), "i"(imm)); \
    r_;                                             \
  })

/** Whole-register byte shift toward higher lanes (pslldq). */
#define WIRED_ARCH_VSHLB(a, imm)                    \
  ({                                                \
    wired_arch_v128 r_ = (a);                       \
    __asm__("pslldq %1, %0" : "+x"(r_) : "i"(imm)); \
    r_;                                             \
  })

/** Whole-register byte shift toward lower lanes (psrldq). */
#define WIRED_ARCH_VSHRB(a, imm)                    \
  ({                                                \
    wired_arch_v128 r_ = (a);                       \
    __asm__("psrldq %1, %0" : "+x"(r_) : "i"(imm)); \
    r_;                                             \
  })

/** One AES round: aesenc (SubBytes/ShiftRows/MixColumns/AddRoundKey). */
static inline wired_arch_v128 wired_arch_aesenc(
    wired_arch_v128 s, wired_arch_v128 rk) {
  __asm__("aesenc %1, %0" : "+x"(s) : "x"(rk));
  return s;
}

/** Final AES round: aesenclast (no MixColumns). */
static inline wired_arch_v128 wired_arch_aesenclast(
    wired_arch_v128 s, wired_arch_v128 rk) {
  __asm__("aesenclast %1, %0" : "+x"(s) : "x"(rk));
  return s;
}

/** ECX feature word of `cpuid` for @p leaf (subleaf 0). */
static inline u32 wired_arch_cpuid_ecx(u32 leaf) {
  u32 a, b, c, d;
  __asm__ volatile("cpuid"
                   : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                   : "a"(leaf), "c"(0u));
  (void)a;
  (void)b;
  (void)d;
  return c;
}

#endif
