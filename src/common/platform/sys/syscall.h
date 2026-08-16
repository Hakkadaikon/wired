#ifndef QUIC_SYS_SYSCALL_H
#define QUIC_SYS_SYSCALL_H

/**
 * @file
 * Linux direct syscalls. No libc.
 *
 * The arch-neutral surface every domain includes: the SDK's fixed-width
 * integer types and the typed `wired_arch_*` syscall wrappers (sysops.h,
 * pulled in via the arch facade). The ISA-specific parts -- SYS_* numbers,
 * the `syscall` instruction sequence, the raw syscallN macros -- live in
 * the arch adapter (`common/arch/`) and are called only from there.
 */

#include "common/arch/arch.h"
#include "common/arch/types.h"

/** Signal numbers used by this SDK (Linux, all architectures). */
#define SIGTERM 15 /**< termination request */

#endif
