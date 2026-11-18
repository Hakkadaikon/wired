#ifndef TEST_SYS_H
#define TEST_SYS_H

/* Syscall numbers only the tests use (the SDK's own are SYS_* in
 * common/arch/): asm-generic/unistd.h on aarch64, asm/unistd_64.h on
 * x86_64. */
#if defined(__aarch64__)
#define TEST_SYS_unlinkat 35
#define TEST_SYS_getsockname 204
#define TEST_SYS_rt_sigpending 136
#else
#define TEST_SYS_unlinkat 263
#define TEST_SYS_getsockname 51
#define TEST_SYS_rt_sigpending 127
#endif

#endif
