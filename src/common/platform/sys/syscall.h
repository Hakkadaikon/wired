#ifndef QUIC_SYS_SYSCALL_H
#define QUIC_SYS_SYSCALL_H

/**
 * @file
 * x86_64 Linux direct syscalls. No libc.
 *
 * Also defines the SDK's fixed-width integer types: with no libc there is no
 * <stdint.h>, so every other header builds on the typedefs here.
 */

typedef unsigned long  u64; /**< unsigned 64-bit integer */
typedef long           i64; /**< signed 64-bit integer */
typedef unsigned int   u32; /**< unsigned 32-bit integer */
typedef int            i32; /**< signed 32-bit integer */
typedef unsigned short u16; /**< unsigned 16-bit integer */
typedef unsigned char  u8;  /**< unsigned 8-bit integer / byte */
typedef i64            ssz; /**< signed size (ssize_t equivalent) */
typedef u64            usz; /**< unsigned size (size_t equivalent) */

#define SYS_read 0                /**< read(2) syscall number */
#define SYS_write 1               /**< write(2) syscall number */
#define SYS_close 3               /**< close(2) syscall number */
#define SYS_rt_sigaction 13       /**< rt_sigaction(2) syscall number */
#define SYS_rt_sigreturn 15       /**< rt_sigreturn(2) syscall number */
#define SYS_socket 41             /**< socket(2) syscall number */
#define SYS_sendmsg 46            /**< sendmsg(2) syscall number */
#define SYS_sendto 44             /**< sendto(2) syscall number */
#define SYS_recvfrom 45           /**< recvfrom(2) syscall number */
#define SYS_bind 49               /**< bind(2) syscall number */
#define SYS_recvmmsg 299          /**< recvmmsg(2) syscall number */
#define SYS_setsockopt 54         /**< setsockopt(2) syscall number */
#define SYS_exit 60               /**< exit(2) syscall number */
#define SYS_sched_setaffinity 203 /**< sched_setaffinity(2) syscall number */
#define SYS_sched_getaffinity 204 /**< sched_getaffinity(2) syscall number */
#define SYS_clock_gettime 228     /**< clock_gettime(2) syscall number */
#define SYS_openat 257            /**< openat(2) syscall number */
#define SYS_getrandom 318         /**< getrandom(2) syscall number */
#define SYS_fork 57               /**< fork(2) syscall number */
#define SYS_wait4 61              /**< wait4(2) syscall number */
#define SYS_exit_group 231        /**< exit_group(2) syscall number */

/** Signal numbers used by this SDK (Linux, all architectures). */
#define SIGTERM 15 /**< termination request */

/** x86_64 Linux rt_sigaction(2) requires SA_RESTORER plus a userspace
 * trampoline that issues rt_sigreturn(2); the kernel refuses a bare handler
 * with no restorer. */
#define SA_RESTORER 0x04000000u

/**
 * Six-argument raw x86_64 Linux syscall.
 *
 * Arguments follow the x86_64 syscall ABI register order: number in rax,
 * then rdi, rsi, rdx, r10, r8, r9. rcx/r11 are clobbered by the `syscall`
 * instruction. The syscall1/syscall3 wrappers pass 0 for their unused
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

/** Three-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall3(n, a, b, c) \
  syscall6((n), (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
/** Four-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall4(n, a, b, c, d) \
  syscall6((n), (i64)(a), (i64)(b), (i64)(c), (i64)(d), 0, 0)
/** One-argument syscall: syscall6() with the trailing arguments zeroed. */
#define syscall1(n, a) syscall6((n), (i64)(a), 0, 0, 0, 0, 0)

#endif
