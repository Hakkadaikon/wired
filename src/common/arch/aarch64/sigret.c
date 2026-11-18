#if defined(__aarch64__)
#include "common/arch/arch.h"

/* Trampoline the kernel jumps to when a signal handler returns: it issues
 * rt_sigreturn(2) itself. naked: a frameless assembly stub. */
__attribute__((naked)) void wired_arch_sigreturn_restorer(void) {
  __asm__ volatile(
      "mov x8, #%0\n"
      "svc #0\n"
      :
      : "i"(SYS_rt_sigreturn));
}
#endif
