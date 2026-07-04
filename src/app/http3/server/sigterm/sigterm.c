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

/* RFC-agnostic Unix convention: SIGHUP's signal number on Linux (all
 * architectures) — not in common/platform/sys/syscall.h because that file is
 * shared with unrelated in-flight work; SIGTERM's constant living there
 * predates this rule and is left as-is. */
#define WIRED_SIGHUP 1

/* Shared registration: both SIGTERM and SIGHUP are handled by the same
 * kernel_sigaction shape and the same rt_sigreturn trampoline, so the two
 * public installers are one-line wrappers over this. */
static int sigterm_install_signal(int sig, void (*handler)(int)) {
  sys_sigaction act = {handler, SA_RESTORER, sigterm_restorer, 0};
  return syscall4(SYS_rt_sigaction, sig, &act, 0, SIGSETSIZE) == 0;
}

int wired_sigterm_install(void (*handler)(int)) {
  return sigterm_install_signal(SIGTERM, handler);
}

int wired_sighup_install(void (*handler)(int)) {
  return sigterm_install_signal(WIRED_SIGHUP, handler);
}
