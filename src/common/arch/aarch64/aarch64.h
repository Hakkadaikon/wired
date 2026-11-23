#ifndef WIRED_ARCH_AARCH64_H
#define WIRED_ARCH_AARCH64_H

/* Only the ISA being compiled for: every header may be included (the
 * sharded test build includes them all). */
#if defined(__aarch64__)

/**
 * @file
 * aarch64 Linux architecture adapter: the same names as x8664.h, for the
 * A64 instruction set. Nothing outside `src/common/arch/` writes inline
 * assembly. Syscall numbers are the generic table every newer Linux ISA
 * uses (include/uapi/asm-generic/unistd.h).
 */

#include "common/arch/types.h"

#define SYS_read 63               /**< read(2) syscall number */
#define SYS_write 64              /**< write(2) syscall number */
#define SYS_close 57              /**< close(2) syscall number */
#define SYS_newfstatat 79         /**< fstatat(2) syscall number */
#define SYS_pread64 67            /**< pread64(2) syscall number */
#define SYS_mmap 222              /**< mmap(2) syscall number */
#define SYS_mprotect 226          /**< mprotect(2) syscall number */
#define SYS_munmap 215            /**< munmap(2) syscall number */
#define SYS_rt_sigaction 134      /**< rt_sigaction(2) syscall number */
#define SYS_rt_sigprocmask 135    /**< rt_sigprocmask(2) syscall number */
#define SYS_rt_sigreturn 139      /**< rt_sigreturn(2) syscall number */
#define SYS_madvise 233           /**< madvise(2) syscall number */
#define SYS_rt_sigtimedwait 137   /**< rt_sigtimedwait(2) syscall number */
#define SYS_socket 198            /**< socket(2) syscall number */
#define SYS_connect 203           /**< connect(2) syscall number */
#define SYS_sendmsg 211           /**< sendmsg(2) syscall number */
#define SYS_sendto 206            /**< sendto(2) syscall number */
#define SYS_recvfrom 207          /**< recvfrom(2) syscall number */
#define SYS_bind 200              /**< bind(2) syscall number */
#define SYS_recvmmsg 243          /**< recvmmsg(2) syscall number */
#define SYS_setsockopt 208        /**< setsockopt(2) syscall number */
#define SYS_clone 220             /**< clone(2) syscall number */
#define SYS_exit 93               /**< exit(2) syscall number */
#define SYS_gettid 178            /**< gettid(2) syscall number */
#define SYS_futex 98              /**< futex(2) syscall number */
#define SYS_sched_setaffinity 122 /**< sched_setaffinity(2) syscall number */
#define SYS_sched_getaffinity 123 /**< sched_getaffinity(2) syscall number */
#define SYS_clock_gettime 113     /**< clock_gettime(2) syscall number */
#define SYS_openat 56             /**< openat(2) syscall number */
#define SYS_mkdirat 34            /**< mkdirat(2) syscall number */
#define SYS_getrandom 278         /**< getrandom(2) syscall number */
#define SYS_wait4 260             /**< wait4(2) syscall number */
#define SYS_kill 129              /**< kill(2) syscall number */
#define SYS_getpid 172            /**< getpid(2) syscall number */
#define SYS_getppid 173           /**< getppid(2) syscall number */
#define SYS_prctl 167             /**< prctl(2) syscall number */
#define SYS_exit_group 94         /**< exit_group(2) syscall number */
#define SYS_ppoll 73              /**< ppoll(2) syscall number */
#define SYS_getsockopt 209        /**< getsockopt(2) syscall number */
#define SYS_fcntl 25              /**< fcntl(2) syscall number */
#define SYS_bpf 280               /**< bpf(2) syscall number */

/** arm64 rt_sigaction(2) honours SA_RESTORER the same way x86_64 does (the
 * kernel jumps to sa_restorer when the handler returns), so one
 * kernel_sigaction layout serves both ISAs. */
#define SA_RESTORER 0x04000000u

/**
 * Six-argument raw aarch64 Linux syscall: number in x8, arguments in
 * x0..x5, `svc #0`, result in x0 (negative values are -errno).
 */
static inline i64 syscall6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 x8 __asm__("x8") = n;
  register i64 x0 __asm__("x0") = a;
  register i64 x1 __asm__("x1") = b;
  register i64 x2 __asm__("x2") = c;
  register i64 x3 __asm__("x3") = d;
  register i64 x4 __asm__("x4") = e;
  register i64 x5 __asm__("x5") = f;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory");
  return x0;
}

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

/** CPU spin-wait hint for busy-poll loops (A64 `yield`). */
static inline void wired_arch_pause(void) { __asm__ volatile("yield"); }

/** Returns x unchanged, but hides its value from the optimizer: a mask
 * built from a secret bit cannot be turned back into a branch or a
 * secret-selected load (constant-time selects; `just ct-check`). */
static inline u64 wired_arch_value_barrier(u64 x) {
  __asm__("" : "+r"(x));
  return x;
}

/**
 * Raw clone(2) whose child starts on a new stack (assembly trampoline in
 * clone.c). Same contract as the x86_64 adapter: the caller stored the
 * child's entry function and its argument in the two 8-byte slots at
 * @p child_stack; the child loads them, calls fn(arg), then exits(0).
 *
 * @param flags CLONE_* flag mask passed straight to the kernel
 * @param child_stack top of the child's stack, seeded with fn and arg
 * @param parent_tid kernel writes the child tid here (CLONE_PARENT_SETTID)
 * @param child_tid cleared+futex-woken on child exit (CLONE_CHILD_CLEARTID)
 * @param tls new TLS descriptor (0 when unused)
 * @return the child tid in the parent, or a negative -errno
 */
i64 wired_arch_clone_raw(
    i64 flags, u8* child_stack, i32* parent_tid, i32* child_tid, i64 tls);

/**
 * Signal-return trampoline for rt_sigaction(2)'s SA_RESTORER slot
 * (assembly in sigret.c). Take its address only.
 */
void wired_arch_sigreturn_restorer(void);

/**
 * Body of a freestanding `_start` (inside a naked function): Linux enters
 * with sp 16-byte aligned pointing at argc, argv right above it. Calls
 * @p entry (`int entry(int argc, char** argv)`) and exits with its return
 * value (already in x0).
 */
#define WIRED_ARCH_START_ASM(entry)  \
  __asm__ volatile(                  \
      "ldr x0, [sp]\n"               \
      "add x1, sp, #8\n"             \
      "bl " #entry                   \
      "\n"                           \
      "mov x8, #93\n" /* SYS_exit */ \
      "svc #0\n")

#endif

#endif
