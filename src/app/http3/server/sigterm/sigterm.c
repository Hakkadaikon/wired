#include "app/http3/server/sigterm/sigterm.h"

/* Linux x86_64 kernel_sigaction ABI (distinct from glibc's struct sigaction):
 * handler, flags, restorer, then a fixed 8-byte mask (sigsetsize below). */
typedef struct {
  void (*sa_handler)(int);
  u64 sa_flags;
  void (*sa_restorer)(void);
  u64 sa_mask;
} sys_sigaction;

/* rt_sigaction(2) always takes sigsetsize == sizeof(u64) on this ABI. */
#define SIGSETSIZE 8u

/* Trampoline the kernel jumps to when the handler returns: it must issue
 * rt_sigreturn(2) itself (no libc `restore_rt` to fall back on here). naked:
 * this is a real, frameless assembly stub, not a callable C function. */
__attribute__((naked)) static void sigterm_restorer(void) {
  __asm__ volatile(
      "mov $%c0, %%rax\n"
      "syscall\n"
      :
      : "i"(SYS_rt_sigreturn));
}

int wired_sigterm_install(void (*handler)(int)) {
  sys_sigaction act = {handler, SA_RESTORER, sigterm_restorer, 0};
  return syscall4(SYS_rt_sigaction, SIGTERM, &act, (void *)0, SIGSETSIZE) == 0;
}
