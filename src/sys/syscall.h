#ifndef QUIC_SYS_SYSCALL_H
#define QUIC_SYS_SYSCALL_H

/* x86_64 Linux direct syscalls. No libc. */

typedef unsigned long  u64;
typedef long           i64;
typedef unsigned int   u32;
typedef int            i32;
typedef unsigned short u16;
typedef unsigned char  u8;
typedef i64            ssz;
typedef u64            usz;

#define SYS_read      0
#define SYS_write     1
#define SYS_close     3
#define SYS_socket    41
#define SYS_sendto    44
#define SYS_recvfrom  45
#define SYS_bind      49
#define SYS_exit      60
#define SYS_clock_gettime 228
#define SYS_getrandom 318

static inline i64 syscall6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f)
{
    i64 ret;
    register i64 r10 __asm__("r10") = d;
    register i64 r8  __asm__("r8")  = e;
    register i64 r9  __asm__("r9")  = f;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

#define syscall3(n, a, b, c) syscall6((n), (i64)(a), (i64)(b), (i64)(c), 0, 0, 0)
#define syscall1(n, a)       syscall6((n), (i64)(a), 0, 0, 0, 0, 0)

#endif
