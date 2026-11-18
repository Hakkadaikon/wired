#ifndef WIRED_ARCH_H
#define WIRED_ARCH_H

/**
 * @file
 * Architecture selection facade. The rest of `src/` consumes ISA-specific
 * functionality (raw syscalls, trampolines, SIMD, spin hints) only through
 * the arch-neutral names declared by the selected adapter below; porting to
 * a new ISA means adding a `src/common/arch/<isa>/` implementation and
 * selecting it in raw.h and simd128.h — no other file changes.
 */

#include "common/arch/raw.h"
#include "common/arch/sysops.h"

#endif
