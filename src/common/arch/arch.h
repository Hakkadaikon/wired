#ifndef WIRED_ARCH_H
#define WIRED_ARCH_H

/**
 * @file
 * Architecture selection facade. The rest of `src/` consumes ISA-specific
 * functionality (raw syscalls, trampolines, SIMD, spin hints) only through
 * the arch-neutral names declared by the selected adapter below; porting to
 * a new ISA means adding a `src/common/arch/<isa>/` implementation and
 * switching the include here — no other file changes.
 */

#include "common/arch/sysops.h"
#include "common/arch/x8664/x8664.h"

#endif
