#include "common/arch/arch.h"

/* Trampoline the kernel jumps to when a signal handler returns: it must
 * issue rt_sigreturn(2) itself (no libc `restore_rt` to fall back on here).
 * naked: this is a real, frameless assembly stub, not a callable C function.
 */
__attribute__((naked)) void wired_arch_sigreturn_restorer(void) {
  __asm__ volatile(
      "mov $%c0, %%rax\n"
      "syscall\n"
      :
      : "i"(SYS_rt_sigreturn));
}
