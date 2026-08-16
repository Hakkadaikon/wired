#ifndef WIRED_ARCH_SYSOPS_H
#define WIRED_ARCH_SYSOPS_H

/**
 * @file
 * Typed wrappers over the raw syscall layer -- the only place outside the
 * arch instruction sequences where `syscallN(SYS_*)` may appear. Every
 * domain calls kernel functionality through these `wired_arch_*` names;
 * the wrappers stay deliberately thin: kernel argument order, pointers as
 * `void*` (callers keep their own struct definitions), and the kernel's
 * raw i64 return where negative values are -errno.
 */

#include "common/arch/x8664/x8664.h" /* raw layer: switched with arch.h */

/** openat(2): open @p path relative to @p dirfd. */
static inline i64 wired_arch_openat(
    i64 dirfd, const char* path, i64 flags, i64 mode) {
  return syscall4(SYS_openat, dirfd, path, flags, mode);
}

/** close(2). */
static inline i64 wired_arch_close(i64 fd) { return syscall1(SYS_close, fd); }

/** read(2). */
static inline i64 wired_arch_read(i64 fd, void* buf, i64 n) {
  return syscall3(SYS_read, fd, buf, n);
}

/** write(2). */
static inline i64 wired_arch_write(i64 fd, const void* buf, i64 n) {
  return syscall3(SYS_write, fd, buf, n);
}

/** pread64(2): read at an explicit offset, file position unmoved. */
static inline i64 wired_arch_pread64(i64 fd, void* buf, i64 n, i64 off) {
  return syscall4(SYS_pread64, fd, buf, n, off);
}

/** newfstatat(2): stat @p path (kernel struct stat into @p st). */
static inline i64 wired_arch_newfstatat(
    i64 dirfd, const char* path, void* st, i64 flags) {
  return syscall4(SYS_newfstatat, dirfd, path, st, flags);
}

/** mkdirat(2). */
static inline i64 wired_arch_mkdirat(i64 dirfd, const char* path, i64 mode) {
  return syscall3(SYS_mkdirat, dirfd, path, mode);
}

/** socket(2). */
static inline i64 wired_arch_socket(i64 domain, i64 type, i64 protocol) {
  return syscall3(SYS_socket, domain, type, protocol);
}

/** bind(2): @p addr is a kernel sockaddr of @p len bytes. */
static inline i64 wired_arch_bind(i64 fd, const void* addr, i64 len) {
  return syscall3(SYS_bind, fd, addr, len);
}

/** setsockopt(2). */
static inline i64 wired_arch_setsockopt(
    i64 fd, i64 level, i64 opt, const void* val, i64 len) {
  return syscall5(SYS_setsockopt, fd, level, opt, val, len);
}

/** getsockopt(2): @p len is an in/out i32*. */
static inline i64 wired_arch_getsockopt(
    i64 fd, i64 level, i64 opt, void* val, void* len) {
  return syscall5(SYS_getsockopt, fd, level, opt, val, len);
}

/** sendto(2): @p addr may be 0/len 0 for connected-style sends. */
static inline i64 wired_arch_sendto(
    i64 fd, const void* buf, i64 n, i64 flags, const void* addr, i64 alen) {
  return syscall6(SYS_sendto, fd, (i64)buf, n, flags, (i64)addr, alen);
}

/** recvfrom(2): @p addr/@p alen may be 0 when the sender is not needed. */
static inline i64 wired_arch_recvfrom(
    i64 fd, void* buf, i64 n, i64 flags, void* addr, void* alen) {
  return syscall6(SYS_recvfrom, fd, (i64)buf, n, flags, (i64)addr, (i64)alen);
}

/** sendmsg(2): @p msg is a kernel struct msghdr. */
static inline i64 wired_arch_sendmsg(i64 fd, const void* msg, i64 flags) {
  return syscall3(SYS_sendmsg, fd, msg, flags);
}

/** recvmmsg(2): @p vec is a kernel struct mmsghdr array of @p n entries. */
static inline i64 wired_arch_recvmmsg(
    i64 fd, void* vec, i64 n, i64 flags, void* timeout) {
  return syscall5(SYS_recvmmsg, fd, vec, n, flags, timeout);
}

/** poll(2): @p fds is a kernel struct pollfd array. */
static inline i64 wired_arch_poll(void* fds, i64 nfds, i64 timeout_ms) {
  return syscall3(SYS_poll, fds, nfds, timeout_ms);
}

/** fcntl(2). */
static inline i64 wired_arch_fcntl(i64 fd, i64 cmd, i64 arg) {
  return syscall3(SYS_fcntl, fd, cmd, arg);
}

/** mmap(2): addresses as i64 (x86_64 user addresses are never negative, so
 * `< 0` on the return is the error test). */
static inline i64 wired_arch_mmap(
    i64 addr, i64 len, i64 prot, i64 flags, i64 fd, i64 off) {
  return syscall6(SYS_mmap, addr, len, prot, flags, fd, off);
}

/** mprotect(2). */
static inline i64 wired_arch_mprotect(i64 addr, i64 len, i64 prot) {
  return syscall3(SYS_mprotect, addr, len, prot);
}

/** munmap(2). */
static inline i64 wired_arch_munmap(i64 addr, i64 len) {
  return syscall2(SYS_munmap, addr, len);
}

/** exit(2): ends the calling thread (last thread ends the process). */
static inline i64 wired_arch_exit(i64 code) { return syscall1(SYS_exit, code); }

/** exit_group(2): ends every thread in the process. */
static inline i64 wired_arch_exit_group(i64 code) {
  return syscall1(SYS_exit_group, code);
}

/** fork(2). */
static inline i64 wired_arch_fork(void) { return syscall1(SYS_fork, 0); }

/** wait4(2). */
static inline i64 wired_arch_wait4(
    i64 pid, void* status, i64 opts, void* rusage) {
  return syscall4(SYS_wait4, pid, status, opts, rusage);
}

/** gettid(2). */
static inline i64 wired_arch_gettid(void) { return syscall1(SYS_gettid, 0); }

/** futex(2). */
static inline i64 wired_arch_futex(
    void* uaddr, i64 op, i64 val, void* timeout, void* uaddr2, i64 val3) {
  return syscall6(
      SYS_futex, (i64)uaddr, op, val, (i64)timeout, (i64)uaddr2, val3);
}

/** clock_gettime(2): @p ts is a kernel struct timespec. */
static inline i64 wired_arch_clock_gettime(i64 clkid, void* ts) {
  return syscall2(SYS_clock_gettime, clkid, ts);
}

/** getrandom(2). */
static inline i64 wired_arch_getrandom(void* buf, i64 n, i64 flags) {
  return syscall3(SYS_getrandom, buf, n, flags);
}

/** sched_getaffinity(2): @p mask is a cpu bitmap of @p len bytes. */
static inline i64 wired_arch_sched_getaffinity(i64 pid, i64 len, void* mask) {
  return syscall3(SYS_sched_getaffinity, pid, len, mask);
}

/** sched_setaffinity(2). */
static inline i64 wired_arch_sched_setaffinity(
    i64 pid, i64 len, const void* mask) {
  return syscall3(SYS_sched_setaffinity, pid, len, mask);
}

/** rt_sigaction(2): @p act/@p old are kernel_sigaction (not glibc's). */
static inline i64 wired_arch_rt_sigaction(
    i64 sig, const void* act, void* old, i64 setsize) {
  return syscall4(SYS_rt_sigaction, sig, act, old, setsize);
}

/** rt_sigprocmask(2): @p set/@p old are u64 signal bitmaps. */
static inline i64 wired_arch_rt_sigprocmask(
    i64 how, const void* set, void* old, i64 setsize) {
  return syscall4(SYS_rt_sigprocmask, how, set, old, setsize);
}

/** bpf(2): @p attr is a kernel union bpf_attr of @p size bytes. */
static inline i64 wired_arch_bpf(i64 cmd, void* attr, i64 size) {
  return syscall3(SYS_bpf, cmd, attr, size);
}

#endif
