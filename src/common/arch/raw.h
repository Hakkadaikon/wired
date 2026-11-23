#ifndef WIRED_ARCH_RAW_H
#define WIRED_ARCH_RAW_H

/**
 * @file
 * The one place the instruction set is chosen: the raw syscall layer,
 * trampolines and spin hint of the ISA being compiled for. Each adapter
 * declares the same names (SYS_* numbers, syscall1..syscall6,
 * wired_arch_pause, wired_arch_value_barrier, wired_arch_clone_raw,
 * wired_arch_sigreturn_restorer, WIRED_ARCH_START_ASM).
 */

#if defined(__aarch64__)
#include "common/arch/aarch64/aarch64.h"
#else
#include "common/arch/x8664/x8664.h"
#endif

#endif
