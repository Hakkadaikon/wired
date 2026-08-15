#ifndef QUIC_SYS_SYSCALL_H
#define QUIC_SYS_SYSCALL_H

/**
 * @file
 * Linux direct syscalls. No libc.
 *
 * The arch-neutral surface every domain includes: the SDK's fixed-width
 * integer types and the syscall1..syscall6 wrappers. The ISA-specific parts
 * (SYS_* numbers, the `syscall` instruction sequence) live in the arch
 * adapter (`common/arch/`); this header is the stable facade over them.
 */

#include "common/arch/arch.h"
#include "common/arch/types.h"

/** Signal numbers used by this SDK (Linux, all architectures). */
#define SIGTERM 15 /**< termination request */

/** Two-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall2(n, a, b) syscall6((n), (i64)(a), (i64)(b), 0, 0, 0, 0)
/** Three-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall3(n, a, b, c) \
  syscall6((n), (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
/** Four-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall4(n, a, b, c, d) \
  syscall6((n), (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
/** Five-argument syscall: syscall6() with the trailing argument zeroed. */
#define syscall5(n, a, b, c, d, e) \
  syscall6((n), (i64)(a), (i64)(b), (i64)(c), (i64)(d), (i64)(e), 0)
/** One-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall1(n, a) syscall6((n), (i64)(a), 0, 0, 0, 0, 0)

#endif
