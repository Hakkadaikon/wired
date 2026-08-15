#ifndef WIRED_ARCH_X8664_H
#define WIRED_ARCH_X8664_H

/**
 * @file
 * x86-64 Linux architecture adapter: every ISA-specific construct the SDK
 * needs, behind the arch-neutral names the rest of `src/` consumes (via
 * `common/arch/arch.h`). Nothing outside `src/common/arch/` writes inline
 * assembly or x86 builtins.
 */

#include "common/arch/types.h"

#define SYS_read 0                /**< read(2) syscall number */
#define SYS_write 1               /**< write(2) syscall number */
#define SYS_close 3               /**< close(2) syscall number */
#define SYS_newfstatat 262        /**< newfstatat(2) syscall number */
#define SYS_pread64 17            /**< pread64(2) syscall number */
#define SYS_mmap 9                /**< mmap(2) syscall number */
#define SYS_mprotect 10           /**< mprotect(2) syscall number */
#define SYS_munmap 11             /**< munmap(2) syscall number */
#define SYS_rt_sigaction 13       /**< rt_sigaction(2) syscall number */
#define SYS_rt_sigprocmask 14     /**< rt_sigprocmask(2) syscall number */
#define SYS_rt_sigreturn 15       /**< rt_sigreturn(2) syscall number */
#define SYS_socket 41             /**< socket(2) syscall number */
#define SYS_sendmsg 46            /**< sendmsg(2) syscall number */
#define SYS_sendto 44             /**< sendto(2) syscall number */
#define SYS_recvfrom 45           /**< recvfrom(2) syscall number */
#define SYS_bind 49               /**< bind(2) syscall number */
#define SYS_recvmmsg 299          /**< recvmmsg(2) syscall number */
#define SYS_setsockopt 54         /**< setsockopt(2) syscall number */
#define SYS_clone 56              /**< clone(2) syscall number */
#define SYS_exit 60               /**< exit(2) syscall number */
#define SYS_gettid 186            /**< gettid(2) syscall number */
#define SYS_futex 202             /**< futex(2) syscall number */
#define SYS_sched_setaffinity 203 /**< sched_setaffinity(2) syscall number */
#define SYS_sched_getaffinity 204 /**< sched_getaffinity(2) syscall number */
#define SYS_clock_gettime 228     /**< clock_gettime(2) syscall number */
#define SYS_openat 257            /**< openat(2) syscall number */
#define SYS_mkdirat 258           /**< mkdirat(2) syscall number */
#define SYS_getrandom 318         /**< getrandom(2) syscall number */
#define SYS_fork 57               /**< fork(2) syscall number */
#define SYS_wait4 61              /**< wait4(2) syscall number */
#define SYS_exit_group 231        /**< exit_group(2) syscall number */

/** x86_64 Linux rt_sigaction(2) requires SA_RESTORER plus a userspace
 * trampoline that issues rt_sigreturn(2); the kernel refuses a bare handler
 * with no restorer. */
#define SA_RESTORER 0x04000000u

/**
 * Six-argument raw x86_64 Linux syscall.
 *
 * Arguments follow the x86_64 syscall ABI register order: number in rax,
 * then rdi, rsi, rdx, r10, r8, r9. rcx/r11 are clobbered by the `syscall`
 * instruction. The syscall1..syscall5 wrappers pass 0 for their unused
 * trailing arguments.
 *
 * @param n syscall number (one of the SYS_* constants)
 * @param a 1st argument (rdi)
 * @param b 2nd argument (rsi)
 * @param c 3rd argument (rdx)
 * @param d 4th argument (r10)
 * @param e 5th argument (r8)
 * @param f 6th argument (r9)
 * @return the kernel's return value; negative values are -errno
 */
static inline i64 syscall6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  i64          ret;
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8")   = e;
  register i64 r9 __asm__("r9")   = f;
  __asm__ volatile("syscall"
                   : "=a"(ret)
                   : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                   : "rcx", "r11", "memory");
  return ret;
}

/** CPU spin-wait hint for busy-poll loops (x86 `pause`): tells the core a
 * spin is in progress, saving power and easing hyperthread contention. */
static inline void wired_arch_pause(void) { __builtin_ia32_pause(); }

/**
 * Raw clone(2) whose child starts on a new stack (assembly trampoline in
 * clone.c; a C wrapper cannot be used because the compiler's spills would
 * read the parent's frame from the child). The caller must have pushed the
 * child's entry function and its argument as the two topmost 8-byte slots
 * of @p child_stack; the child pops them, calls fn(arg), then exits(0).
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
 * Signal-return trampoline for rt_sigaction(2)'s SA_RESTORER slot: the
 * kernel jumps here when a handler returns, and the stub issues
 * rt_sigreturn(2) (assembly in sigret.c; there is no libc `restore_rt` to
 * fall back on). Take its address only -- it is not a callable C function.
 */
void wired_arch_sigreturn_restorer(void);

/**
 * Body of a freestanding `_start` (to be used inside a naked function):
 * Linux enters with RSP%16==0 and no return address on the stack; this
 * recovers argc (rdi) and argv (rsi) from the kernel-built initial stack,
 * 16-byte-aligns RSP for the SysV ABI's post-call state, calls @p entry
 * (`int entry(int argc, char** argv)`), and exits with its return value.
 */
#define WIRED_ARCH_START_ASM(entry)    \
  __asm__ volatile(                    \
      "mov (%rsp), %rdi\n"             \
      "lea 8(%rsp), %rsi\n"            \
      "and $-16, %rsp\n"               \
      "call " #entry                   \
      "\n"                             \
      "mov %eax, %edi\n"               \
      "mov $60, %eax\n" /* SYS_exit */ \
      "syscall\n")

#endif
