#ifndef WIRED_ARCH_SIMD128_H
#define WIRED_ARCH_SIMD128_H

/**
 * @file
 * 128-bit SIMD wrappers of the ISA being compiled for: wired_arch_v128,
 * WIRED_ARCH_CLMUL / WIRED_ARCH_VSHLB / WIRED_ARCH_VSHRB, wired_arch_aesenc,
 * wired_arch_aesenclast, wired_arch_pshufb, and wired_arch_aes_clmul_ok
 * (whether this CPU has the AES and carry-less multiply instructions).
 */

#if defined(__aarch64__)
#include "common/arch/aarch64/simd128.h"
#else
#include "common/arch/x8664/simd128.h"
#endif

#endif
